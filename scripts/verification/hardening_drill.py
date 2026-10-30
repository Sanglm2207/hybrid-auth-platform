#!/usr/bin/env python3
"""Disposable P0/P1/P2 hardening drill. Requires built jars, JDK25 and Docker.
Only generated PostgreSQL/Redis containers and loopback SMTP are mutated.
"""
import os,json,subprocess,tempfile,time,socket,threading,urllib.request,urllib.error
from pathlib import Path
from smtp_sink import SMTPServer
from concurrent.futures import ThreadPoolExecutor
import base64, statistics, shutil
root=Path(__file__).resolve().parents[2]; containers=[]; processes=[]; logs=[]; mail=None
java=str(Path(os.environ['JAVA_HOME'])/'bin/java') if os.environ.get('JAVA_HOME') else shutil.which('java')
if not os.environ.get('JAVA_HOME') and Path('/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home/bin/java').exists():java='/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home/bin/java'
assert java,'JDK 25 is required'
KEY='p2-internal-identity-service-test-key-0123456789'; PROXY='p2-gateway-proxy-test-key-at-least-32-characters'
def docker(*args,stdin=None,ok=True):
 result=subprocess.run(['docker',*args],input=stdin,capture_output=True,text=True,timeout=60)
 assert (result.returncode==0)==ok, 'Unexpected Docker command result: '+args[0]
 return result.stdout.strip()
def port():
 with socket.socket() as sock: sock.bind(('127.0.0.1',0)); return sock.getsockname()[1]
def call(server,path,payload=None,token=None,expected=200,method='POST',headers=None):
 data=json.dumps(payload).encode() if payload is not None else (None if method=='GET' else b'')
 values={'Content-Type':'application/json','User-Agent':'P2 Smoke Browser'}
 if token: values['Authorization']='Bearer '+token
 if headers: values.update(headers)
 req=urllib.request.Request(f'http://127.0.0.1:{server}{path}',data=data,headers=values,method=method)
 try:
  with urllib.request.urlopen(req,timeout=30) as response: code=response.status; body=json.load(response)
 except urllib.error.HTTPError as response: code=response.code; body=json.load(response)
 assert code==expected, f'{method} {path}: expected {expected}, got {code} ({body.get("code","unknown")})'
 return body
def wait(server,process):
 for _ in range(300):
  if process.poll() is not None: raise RuntimeError('Isolated service exited during startup')
  try:
   with urllib.request.urlopen(f'http://127.0.0.1:{server}/actuator/health',timeout=1) as response:
    if response.status==200: return
  except Exception: time.sleep(.1)
 raise RuntimeError('Isolated service startup timeout')
def boot(module,server,env,temp):
 log=(temp/(module+str(server)+'.log')).open('w'); logs.append(log)
 settings=os.environ.copy(); settings.update(env); settings['SERVER_PORT']=str(server)
 process=subprocess.Popen([java,'-jar',str(root/module/'target'/f'{module}-1.0.0.jar')],env=settings,stdout=log,stderr=log)
 processes.append(process)
 try: wait(server,process)
 except Exception:
  log.flush(); Path('/tmp/hybrid-p2-'+module+'-failure.log').write_text((temp/(module+str(server)+'.log')).read_text()); raise
 return process
try:
 with tempfile.TemporaryDirectory(prefix='hybrid-p2-smoke-') as directory:
  temp=Path(directory)
  pg=docker('run','--rm','-d','-p','127.0.0.1::5432','-e','POSTGRES_DB=authdb','-e','POSTGRES_USER=auth','-e','POSTGRES_PASSWORD=auth-test-password','-e','PROFILE_DB_PASSWORD=profile-test-password','-e','AUTH_APP_PASSWORD=auth-app-test','-e','AUTH_MIGRATION_PASSWORD=auth-migr-test','-e','PROFILE_APP_PASSWORD=profile-app-test','-e','MAIL_APP_PASSWORD=mail-app-test','-e','MAIL_MIGRATION_PASSWORD=mail-migr-test','-v',str(root/'infra/postgres/init-user-db.sql')+':/docker-entrypoint-initdb.d/01-user-db.sql:ro','postgres:17-alpine'); containers.append(pg)
  redis=docker('run','--rm','-d','-p',f'127.0.0.1:{port()}:6379','redis:7.4-alpine','redis-server','--appendonly','yes','--appendfsync','always','--maxmemory-policy','noeviction'); containers.append(redis)
  pgport=int(docker('port',pg,'5432/tcp').rsplit(':',1)[1]); redisport=int(docker('port',redis,'6379/tcp').rsplit(':',1)[1])
  for _ in range(100):
   ready=subprocess.run(['docker','exec',pg,'pg_isready','-h','127.0.0.1','-U','auth','-d','authdb'],capture_output=True)
   if ready.returncode==0: break
   time.sleep(.1)
  else: raise RuntimeError('Isolated PostgreSQL did not become ready')
  private=temp/'private.pem'; public=temp/'public.pem'
  subprocess.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',str(private)],check=True,capture_output=True)
  subprocess.run(['openssl','pkey','-in',str(private),'-pubout','-out',str(public)],check=True,capture_output=True)
  mail=SMTPServer(); threading.Thread(target=mail.serve_forever,daemon=True).start()
  mailport=port()
  manifest=temp/'jwt.json'
  def keys(operation,kid):
   env=os.environ.copy();env['PATH']=str(Path(java).parent)+os.pathsep+env.get('PATH','')
   subprocess.run(['python3',str(root/'scripts/jwt-keys.py'),operation,'--manifest',str(manifest),'--private-pem',str(private),'--kid',kid],env=env,check=True,capture_output=True)
  keys('init','drill-1')
  auth,user,gateway=port(),port(),port()
  common=dict(JWT_ISSUER=f'http://localhost:{auth}',JWKS_URI=f'http://127.0.0.1:{auth}/.well-known/jwks.json',IDENTITY_SERVICE_URL=f'http://127.0.0.1:{auth}',IDENTITY_SERVICE_KEY=KEY,AUTH_PROXY_KEY=PROXY,AUDIT_LOG_PATH=str(temp/'audit'),SERVICE_BIND_ADDRESS='127.0.0.1')
  authenv=dict(common,USER_URL=f'http://127.0.0.1:{user}',DB_URL=f'jdbc:postgresql://127.0.0.1:{pgport}/authdb',AUTH_DB_USERNAME='auth_app',AUTH_APP_PASSWORD='auth-app-test',AUTH_MIGRATION_PASSWORD='auth-migr-test',MAIL_OUTBOX_ENCRYPTION_KEY='34'*32,LOGIN_IP_LIMIT='200',AUTH_IP_LIMIT='1000',REDIS_HOST='127.0.0.1',REDIS_PORT=str(redisport),JWT_KEY_SET=str(manifest),JWT_PRIVATE_KEY=str(private),JWT_PUBLIC_KEY=str(public),MAIL_SERVICE_URL=f'http://127.0.0.1:{mailport}',MAIL_SERVICE_API_KEY='p2-smoke-mail-key')
  boot('mail-service',mailport,dict(MAIL_SERVICE_PORT=str(mailport),MAIL_DB_URL=f'jdbc:postgresql://127.0.0.1:{pgport}/maildb',MAIL_APP_PASSWORD='mail-app-test',MAIL_MIGRATION_PASSWORD='mail-migr-test',MAIL_SERVICE_API_KEY='p2-smoke-mail-key',SMTP_HOST='127.0.0.1',SMTP_PORT=str(mail.server_address[1]),EMAIL_FROM='Team <security@example.com>',SPRING_APPLICATION_JSON=json.dumps({'spring':{'mail':{'properties':{'mail.smtp.auth':False,'mail.smtp.starttls.enable':False,'mail.smtp.starttls.required':False}}}})),temp)
  authprocess=boot('auth-service',auth,authenv,temp)
  second=port();secondprocess=boot('auth-service',second,authenv,temp)
  userprocess=boot('user-service',user,dict(common,USER_DB_URL=f'jdbc:postgresql://127.0.0.1:{pgport}/userdb',USER_DB_USERNAME='profiles_app',PROFILE_DB_PASSWORD='profile-test-password',PROFILE_APP_PASSWORD='profile-app-test'),temp)
  boot('api-gateway',gateway,dict(common,AUTH_URL=f'http://127.0.0.1:{auth}',USER_URL=f'http://127.0.0.1:{user}',GATEWAY_TRUSTED_PROXIES='127.0.0.1'),temp)
  base='/api/v1/auth'; pw='CurrentPassword123!'
  for email in ['owner@example.com','admin@example.com','managed@example.com']:
   call(gateway,base+'/register',{'email':email,'password':pw},expected=201)
   import re
   for attempt in range(200):
    with mail.mutex: sent=[m for m in mail.messages if email in str(m['To']) and m['Subject']=='Verify your email']
    if sent: break
    time.sleep(.1)
   assert sent,'Verification email did not reach loopback SMTP'
   text=sent[-1].get_body(preferencelist=('plain',)).get_content()
   assert 'Hybrid Auth Security Team' in text
   otp=re.search(r'\b[0-9]{6}\b',text).group()
   call(gateway,base+'/verify-email',{'email':email,'otp':otp})
  deviceA='11111111-1111-4111-8111-111111111111'; deviceB='22222222-2222-4222-8222-222222222222'
  a=call(gateway,base+'/login',{'email':'owner@example.com','password':pw},headers={'X-Device-Id':deviceA,'X-Forwarded-For':'198.51.100.9','X-Gateway-Resolved-Client':'1.2.3.4'})['data']
  b=call(gateway,base+'/login',{'email':'owner@example.com','password':pw},headers={'X-Device-Id':deviceB})['data']
  listed=call(gateway,base+'/sessions',token=a['accessToken'],method='GET')['data']; assert len(listed)==2
  assert next(s for s in listed if s['deviceId']==deviceA)['ip']=='198.51.100.9', 'Trusted ingress IP was not propagated securely'
  assert len(call(gateway,base+'/devices',token=a['accessToken'],method='GET')['data'])==2
  profile=call(gateway,'/api/v1/users/me',token=a['accessToken'],method='GET',headers={'X-Request-Id':os.environ['P5_PROBE_ID']} if os.environ.get('P5_PROBE_ID') else None)['data']; ownerId=profile['id']
  call(gateway,'/api/v1/users/me',{'displayName':'Kai','locale':'vi-VN','timeZone':'Asia/Ho_Chi_Minh'},a['accessToken'],method='PATCH')
  assert call(user,'/api/v1/users/me',token=a['accessToken'],method='GET')['data']['displayName']=='Kai'
  call(gateway,base+'/roles',token=a['accessToken'],method='GET',expected=403)
  docker('exec','-i',pg,'psql','-v','ON_ERROR_STOP=1','-U','auth','-d','authdb',stdin="BEGIN; INSERT INTO identity_user_roles(user_id,role_name) SELECT id,'ADMIN' FROM app_users WHERE email='admin@example.com'; UPDATE app_users SET credential_revision=credential_revision+1 WHERE email='admin@example.com'; COMMIT;")
  admin=call(gateway,base+'/login',{'email':'admin@example.com','password':pw})['data']
  # Account access extension: actual service boundaries and durable PostgreSQL state.
  managed=call(gateway,base+'/login',{'email':'managed@example.com','password':pw})['data']
  managedId=call(gateway,'/api/v1/users/me',token=managed['accessToken'],method='GET')['data']['id']
  call(gateway,'/api/v1/users/me',{'displayName':'Managed account','bio':'private export data'},managed['accessToken'],method='PATCH')
  credential=call(gateway,base+'/api-keys',{'name':'drill-worker','scopes':['profile:read'],'expiresAt':'2099-01-01T00:00:00Z','currentPassword':pw},managed['accessToken'],expected=400)
  import datetime
  expiry=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=1)).isoformat()
  credential=call(gateway,base+'/api-keys',{'name':'drill-worker','scopes':['profile:read'],'expiresAt':expiry,'currentPassword':pw},managed['accessToken'])['data']
  machine=call(gateway,base+'/service-tokens',headers={'X-Api-Key':credential['secret']})['data']
  call(gateway,'/api/v1/users/me',token=machine['accessToken'],method='GET')
  call(user,'/api/v1/users/me',{'bio':'denied'},machine['accessToken'],method='PATCH',expected=403)
  call(gateway,base+'/api-keys/'+credential['key']['id'],token=managed['accessToken'],method='DELETE')
  call(user,'/api/v1/users/me',token=machine['accessToken'],method='GET',expected=401)
  assert call(gateway,base+'/introspect',{'token':managed['refreshToken']},managed['accessToken'])['data']['active']
  assert call(gateway,base+'/login-history?successful=true',token=managed['accessToken'],method='GET')['data']
  found=call(gateway,base+'/users?q=managed',token=admin['accessToken'],method='GET')['data'];assert len(found)==1 and found[0]['id']==managedId
  tenant=call(gateway,base+'/tenants',{'name':'Drill team','currentPassword':pw},admin['accessToken'])['data']['id']
  call(gateway,base+'/tenants/'+tenant+'/members/'+managedId,{'currentPassword':pw},admin['accessToken'],method='PUT')
  call(gateway,'/api/v1/users/'+managedId+'?tenantId='+tenant,token=admin['accessToken'],method='GET')
  call(user,'/api/v1/users/'+managedId,token=admin['accessToken'],method='GET',expected=403)
  call(user,'/api/v1/users/'+managedId+'?tenantId='+tenant,{'bio':'tenant-authorized update'},admin['accessToken'],method='PATCH')
  call(gateway,base+'/tenants/'+tenant+'/members/'+managedId,{'currentPassword':pw},admin['accessToken'],method='DELETE')
  call(user,'/api/v1/users/'+managedId+'?tenantId='+tenant,token=admin['accessToken'],method='GET',expected=403)
  call(gateway,base+'/tenants/'+tenant,{'currentPassword':pw},admin['accessToken'],method='DELETE')
  call(gateway,base+'/users/'+managedId+'/status',{'status':'SUSPENDED','currentPassword':pw},admin['accessToken'],method='PATCH')
  call(user,'/api/v1/users/me',token=managed['accessToken'],method='GET',expected=401)
  call(gateway,base+'/login',{'email':'managed@example.com','password':pw},expected=403)
  call(gateway,base+'/users/'+managedId+'/status',{'status':'ENABLED','currentPassword':pw},admin['accessToken'],method='PATCH')
  call(user,'/api/v1/users/me',token=managed['accessToken'],method='GET',expected=401)
  managed=call(gateway,base+'/login',{'email':'managed@example.com','password':pw})['data']
  device=call(gateway,base+'/devices',token=managed['accessToken'],method='GET')['data'][0]['id']
  call(gateway,base+'/devices/'+device+'/trust',{'days':30,'currentPassword':pw},managed['accessToken'])
  assert any(d['trusted'] for d in call(gateway,base+'/devices',token=managed['accessToken'],method='GET')['data'])
  currentSession=call(gateway,base+'/session/current',token=managed['accessToken'],method='GET')['data'];assert currentSession['current']
  stepup=call(gateway,base+'/reauthenticate',{'currentPassword':pw},managed['accessToken'])['data']['reauthenticationToken']
  exported=call(gateway,'/api/v1/users/me/export',token=managed['accessToken'],method='GET',headers={'X-Reauthentication-Token':stepup})['data'];assert exported['profile']['bio']=='tenant-authorized update'
  assert 'passwordHash' not in json.dumps(exported) and 'secret_hash' not in json.dumps(exported)
  call(gateway,'/api/v1/users/me',{'currentPassword':pw},managed['accessToken'],method='DELETE',expected=202)
  call(user,'/api/v1/users/me',token=managed['accessToken'],method='GET',expected=401)
  for attempt in range(200):
   deletion=call(gateway,base+'/users/'+managedId+'/deletion',token=admin['accessToken'],method='GET')['data']
   if deletion['state']=='COMPLETED':break
   time.sleep(.1)
  assert deletion['state']=='COMPLETED','Cross-service account erasure did not complete'
  call(user,'/internal/users/'+managedId+'/profile',method='GET',headers={'X-Identity-Service-Key':KEY},expected=404)
  print('Account access drill passed: scoped machine JWT, live revocation, introspection, history, tenant/ownership policy, admin lock/unlock, trusted devices, export and cross-service deletion.')
  call(gateway,base+'/roles',{'name':'VIEWER','permissions':['profile:read','sessions:read'],'currentPassword':pw},admin['accessToken'])
  call(gateway,base+'/users/'+ownerId+'/roles',{'roles':['VIEWER'],'currentPassword':pw},admin['accessToken'],method='PUT')
  call(gateway,'/api/v1/users/me',token=a['accessToken'],method='GET',expected=401)
  call(user,'/api/v1/users/me',token=a['accessToken'],method='GET',expected=401)
  call(auth,base+'/refresh',{'refreshToken':a['refreshToken']},expected=401)
  current=call(gateway,base+'/login',{'email':'owner@example.com','password':pw},headers={'X-Device-Id':deviceA})['data']
  call(gateway,'/api/v1/users/me',{'bio':'denied'},current['accessToken'],method='PATCH',expected=403)
  call(user,'/api/v1/users/me',{'bio':'denied'},current['accessToken'],method='PATCH',expected=403)
  permissions=['profile:read','profile:write','sessions:read','sessions:revoke','devices:read','devices:revoke','account:deactivate']
  call(gateway,base+'/roles/VIEWER/permissions',{'name':'VIEWER','permissions':permissions,'currentPassword':pw},admin['accessToken'],method='PUT')
  call(gateway,'/api/v1/users/me',{'bio':'live permissions'},current['accessToken'],method='PATCH')
  other=call(gateway,base+'/login',{'email':'owner@example.com','password':pw},headers={'X-Device-Id':deviceB})['data']
  listed=call(gateway,base+'/sessions',token=current['accessToken'],method='GET')['data']; target=next(s for s in listed if not s['current'])
  call(gateway,base+'/sessions/'+target['id'],token=current['accessToken'],method='DELETE')
  call(gateway,'/api/v1/users/me',token=other['accessToken'],method='GET',expected=401)
  call(user,'/api/v1/users/me',token=other['accessToken'],method='GET',expected=401)
  call(auth,base+'/refresh',{'refreshToken':other['refreshToken']},expected=401)
  call(gateway,base+'/devices/'+deviceB,token=current['accessToken'],method='DELETE')
  assert len(call(gateway,base+'/devices',token=current['accessToken'],method='GET')['data'])==1
  # Old JWTs remain usable through staged key activation on BOTH Auth nodes.
  keys('stage','drill-2');time.sleep(6);keys('activate','drill-2');time.sleep(6)
  rotated=call(second,base+'/login',{'email':'owner@example.com','password':pw})['data']
  kid=json.loads(base64.urlsafe_b64decode(rotated['accessToken'].split('.')[0]+'=='))['kid'];assert kid=='drill-2'
  call(gateway,'/api/v1/users/me',token=rotated['accessToken'],method='GET')
  call(gateway,'/api/v1/users/me',token=current['accessToken'],method='GET')
  # Two instances race to rotate the same refresh: one succeeds, replay revokes its family.
  def refresh(node):
   try:call(node,base+'/refresh',{'refreshToken':rotated['refreshToken']});return 200
   except AssertionError as error:
    assert 'got 401' in str(error);return 401
  with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(refresh,[auth,second]))
  assert sorted(results)==[200,401]
  call(gateway,'/api/v1/users/me',token=rotated['accessToken'],method='GET',expected=401)
  # Actual concurrent authorized traffic; this is a local baseline, not a production SLA.
  def request_latency(index):
   start=time.perf_counter();call(gateway,'/api/v1/users/me',token=current['accessToken'],method='GET');return (time.perf_counter()-start)*1000
  with ThreadPoolExecutor(max_workers=8) as pool:latencies=sorted(pool.map(request_latency,range(80)))
  print(json.dumps({'requests':80,'concurrency':8,'errors':0,'p50_ms':round(statistics.median(latencies),2),'p95_ms':round(latencies[75],2)}))
  if os.environ.get('P5_PROBE_ID'):
   docker('pause',redis)
   try:call(auth,base+'/login',{'email':'admin@example.com','password':pw},expected=503)
   finally:docker('unpause',redis)
  if os.environ.get('P6_FAILURE_INJECTION') == 'true':
   # Only isolated containers created above are paused. Liveness must remain UP.
   for node in (auth,second,user,gateway,mailport):
    call(node,'/actuator/health/liveness',method='GET')
    call(node,'/actuator/health/readiness',method='GET')
   for dependency,probe in ((redis,auth),(pg,user)):
    docker('pause',dependency)
    try:
     start=time.monotonic()
     call(probe,'/actuator/health/readiness',method='GET',expected=503)
     assert time.monotonic()-start < 12, 'Readiness hung on paused dependency'
     call(probe,'/actuator/health/liveness',method='GET')
     call(auth,base+'/login',{'email':'admin@example.com','password':pw},expected=503)
    finally:docker('unpause',dependency)
    for attempt in range(100):
     try:call(probe,'/actuator/health/readiness',method='GET');break
     except (AssertionError,urllib.error.URLError):time.sleep(.2)
    else:raise AssertionError('Readiness did not recover')
   userprocess.terminate();userprocess.wait(timeout=35)
   call(gateway,'/api/v1/users/me',token=current['accessToken'],method='GET',expected=502)
   call(gateway,'/actuator/health/liveness',method='GET')
   userprocess=boot('user-service',user,dict(common,USER_DB_URL=f'jdbc:postgresql://127.0.0.1:{pgport}/userdb',USER_DB_USERNAME='profiles_app',PROFILE_DB_PASSWORD='profile-test-password',PROFILE_APP_PASSWORD='profile-app-test'),temp)
   call(gateway,'/api/v1/users/me',token=current['accessToken'],method='GET')
   print('P6 failure injection passed: Redis/PostgreSQL readiness DOWN, liveness UP, bounded fail-closed login, recovery, User outage/restart.')
  # PostgreSQL enforces read-only transactions: explicitly exercise activity after the throttle interval.
  docker('exec',pg,'psql','-v','ON_ERROR_STOP=1','-U','auth','-d','authdb','-c',"UPDATE identity_sessions SET last_activity_at=CURRENT_TIMESTAMP-INTERVAL '60 seconds' WHERE revoked_at IS NULL")
  call(gateway,'/api/v1/users/me',token=current['accessToken'],method='GET')
  # Loss of the complete Redis data set cannot resurrect SQL-revoked sessions.
  docker('exec',redis,'redis-cli','FLUSHALL')
  call(gateway,'/api/v1/users/me',token=other['accessToken'],method='GET',expected=401)
  call(second,base+'/refresh',{'refreshToken':other['refreshToken']},expected=401)
  call(gateway,'/api/v1/users/me',token=current['accessToken'],method='GET')
  call(second,base+'/login',{'email':'owner@example.com','password':pw})
  docker('exec',redis,'redis-cli','SET','drill:marker','persistent');docker('restart',redis)
  assert docker('exec',redis,'redis-cli','GET','drill:marker')=='persistent'
  time.sleep(3)  # Auth Redis clients reconnect after the isolated restart.
  # Scoped runtime users cannot create tables, connect across services or edit audit history.
  def sql_as(role,password,database,statement,allowed):
   docker('exec','-e','PGPASSWORD='+password,pg,'psql','-h','127.0.0.1','-v','ON_ERROR_STOP=1','-U',role,'-d',database,'-c',statement,ok=allowed)
  for role,password,database in [('auth_app','auth-app-test','authdb'),('profiles_app','profile-app-test','userdb'),('mailer_app','mail-app-test','maildb')]:
   sql_as(role,password,database,'CREATE TABLE forbidden(id int)',False)
   sql_as(role,password,'userdb' if database=='authdb' else 'authdb','SELECT 1',False)
  sql_as('auth_app','auth-app-test','authdb','UPDATE security_audit_records SET event=event',False)
  sql_as('auth_app','auth-app-test','authdb','DELETE FROM security_audit_records',False)
  sql_as('auth_app','auth-app-test','authdb',"SELECT actor,target,details FROM security_audit_records WHERE event='ROLES_CHANGED' AND actor IS NOT NULL AND target IS NOT NULL",True)
  # SMTP outage is absorbed by outbox, then retries through the real Mail service.
  with mail.mutex: before=len(mail.messages)
  mail.available=False
  call(gateway,base+'/forgot-password',{'email':'owner@example.com'})
  time.sleep(3);mail.available=True
  for attempt in range(200):
   with mail.mutex: delivered=any(m['Subject']=='Reset your password' for m in mail.messages[before:])
   if delivered:break
   time.sleep(.1)
  assert delivered,'Outbox did not recover from SMTP outage'
  # Guard is enforced on PostgreSQL, beyond the H2 unit/integration checks.
  adminId=call(gateway,'/api/v1/users/me',token=admin['accessToken'],method='GET')['data']['id']
  call(gateway,base+'/users/'+adminId+'/roles',{'roles':['USER'],'currentPassword':pw},admin['accessToken'],method='PUT',expected=409)
  if os.environ.get('P4_ZAP') == 'true':
   from zap_api_scan import scan
   scan(user,current['accessToken'])
  call(gateway,base+'/deactivate',{'currentPassword':pw},current['accessToken'])
  call(gateway,'/api/v1/users/me',token=current['accessToken'],method='GET',expected=401)
  call(user,'/api/v1/users/me',token=current['accessToken'],method='GET',expected=401)
  call(gateway,base+'/login',{'email':'owner@example.com','password':pw},expected=403)
  call(gateway,'/api/v1/users/me',token=admin['accessToken'],method='GET')
  docker('exec',pg,'psql','-U','profiles','-d','authdb','-c','SELECT count(*) FROM app_users;',ok=False)
  authprocess.terminate(); authprocess.wait(timeout=10);secondprocess.terminate();secondprocess.wait(timeout=10)
  call(gateway,'/api/v1/users/me',token=admin['accessToken'],method='GET',expected=503)
  call(user,'/api/v1/users/me',token=admin['accessToken'],method='GET',expected=503)
  # Restart preserves valid SQL sessions and the same staged key set.
  authprocess=boot('auth-service',auth,authenv,temp)
  # Downstream connection pools may reject the first request on a stale socket after restart.
  for attempt in range(50):
   try:
    call(gateway,'/api/v1/users/me',token=admin['accessToken'],method='GET');break
   except AssertionError as error:
    if 'got 503' not in str(error) or attempt==49:raise
    time.sleep(.2)
  print('Hardening drill passed: real PostgreSQL, Redis AOF restart/loss, two Auth instances, refresh replay, JWT rotation, scoped database roles, SMTP retry, admin guard, concurrent traffic, identity outage/recovery. No external email sent.')
finally:
 for process in reversed(processes):
  if process.poll() is None:
   process.terminate()
   try: process.wait(timeout=10)
   except subprocess.TimeoutExpired: process.kill(); process.wait()
 if mail: mail.shutdown(); mail.server_close()
 for log in logs: log.close()
 for container in reversed(containers): subprocess.run(['docker','rm','-f',container],capture_output=True,timeout=30)
