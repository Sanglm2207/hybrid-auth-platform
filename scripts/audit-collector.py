#!/usr/bin/env python3
"""Collect service audit files with durable cursors and deduplication; no credentials accepted."""
import argparse, gzip, hashlib, json, re, sqlite3, time, uuid
from collections import Counter
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer


def safe_uuid(value):
    try: return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError): return None


class Collector:
    def __init__(self, source, database):
        self.source = Path(source)
        self.db = sqlite3.connect(database)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('CREATE TABLE IF NOT EXISTS cursors (path TEXT PRIMARY KEY, position INTEGER NOT NULL)')
        if 'complete' not in {row[1] for row in self.db.execute('PRAGMA table_info(cursors)')}:
            self.db.execute('ALTER TABLE cursors ADD COLUMN complete INTEGER NOT NULL DEFAULT 0')
        self.db.execute('CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, service TEXT, timestamp REAL, event TEXT, outcome TEXT, actor TEXT, target TEXT, trace TEXT)')
        if 'details' not in {row[1] for row in self.db.execute('PRAGMA table_info(events)')}:
            self.db.execute("ALTER TABLE events ADD COLUMN details TEXT NOT NULL DEFAULT '{}'")
        self.db.execute('CREATE INDEX IF NOT EXISTS events_time ON events(timestamp)')
        self.db.execute('CREATE TABLE IF NOT EXISTS totals (event TEXT, outcome TEXT, count INTEGER, PRIMARY KEY(event,outcome))')
        self.db.execute('INSERT OR IGNORE INTO totals SELECT event,outcome,count(*) FROM events GROUP BY event,outcome')
        self.db.execute('CREATE TABLE IF NOT EXISTS alerts (rule TEXT, bucket INTEGER, count INTEGER, PRIMARY KEY(rule,bucket))')
        self.db.commit()

    def collect(self):
        from datetime import datetime
        for path in sorted(self.source.rglob('*.jsonl*')):
            try:self.collect_file(path,datetime)
            except (FileNotFoundError,EOFError,gzip.BadGzipFile):pass

    def collect_file(self,path,datetime):
        if not path.is_file(): return
        stat = path.stat()
        identity = f'{stat.st_dev}:{stat.st_ino}:{path.suffix == ".gz"}'
        row = self.db.execute('SELECT position,complete FROM cursors WHERE path=?', (identity,)).fetchone()
        if row and row[1] and path.suffix == '.gz': return
        position = row[0] if row else 0
        # A truncated current file starts a new stream; event hash still deduplicates it.
        if path.suffix != '.gz' and position > stat.st_size: position = 0
        opener = gzip.open if path.suffix == '.gz' else open
        with opener(path, 'rb') as stream:
            stream.seek(position)
            complete=0
            for _ in range(10000):
                start = stream.tell(); line = stream.readline()
                if not line: complete=1;break
                if not line.endswith(b'\n'): stream.seek(start); break
                try:
                    item = json.loads(line)
                    event, outcome = item['event'], item['outcome']
                    if not isinstance(event, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}',event): continue
                    if outcome not in ('SUCCESS','FAILURE','DENIED','UNAVAILABLE'): continue
                    stamp = datetime.fromisoformat(item['timestamp'].replace('Z','+00:00')).timestamp()
                    details=item.get('details',{})
                    if not isinstance(details,dict): details={}
                    safe={key:safe_uuid(details[key]) for key in ('targetUserId','sessionId','deviceId') if key in details}
                    if isinstance(details.get('role'),str) and re.fullmatch(r'[A-Z][A-Z0-9_]{0,31}',details['role']):safe['role']=details['role']
                    for key in ('rolesBefore','rolesAfter','permissionsBefore','permissionsAfter'):
                        if isinstance(details.get(key),list):safe[key]=[v for v in details[key][:64] if isinstance(v,str) and re.fullmatch(r'[A-Z][A-Z0-9_]{0,31}|[a-z]+:[a-z]+',v)]
                    inserted=self.db.execute('INSERT OR IGNORE INTO events(id,service,timestamp,event,outcome,actor,target,trace,details) VALUES(?,?,?,?,?,?,?,?,?)', (
                        hashlib.sha256(line).hexdigest(), path.name.split('.')[0], stamp, event, outcome,
                        safe_uuid(item.get('actor')), safe_uuid(details.get('targetUserId')), safe_uuid(item.get('traceId')),json.dumps(safe,sort_keys=True)))
                    if inserted.rowcount:self.db.execute('INSERT INTO totals VALUES(?,?,1) ON CONFLICT(event,outcome) DO UPDATE SET count=count+1',(event,outcome))
                except (ValueError, KeyError, TypeError, AttributeError, OverflowError): pass
            self.db.execute('INSERT OR REPLACE INTO cursors VALUES(?,?,?)', (identity,stream.tell(),complete))
        self.db.commit()


    def metrics(self):
        counts = Counter({(event,outcome): count for event,outcome,count in self.db.execute('SELECT event,outcome,count FROM totals')})
        rows = ['# TYPE hybrid_security_events_total counter']
        for (event,outcome),count in sorted(counts.items()):
            rows.append(f'hybrid_security_events_total{{event="{event}",outcome="{outcome}"}} {count}')
        now = time.time()
        rules = {'refresh_reuse':("event='REFRESH_REUSE'",1), 'state_unavailable':("event='SECURITY_STATE_FAILURE'",1),
                 'login_failures':("event='LOGIN' AND outcome='DENIED'",30), 'mail_failures':("event='ACCOUNT_MAIL_FAILURE'",10)}
        rows.append('# TYPE hybrid_security_alert gauge')
        for name,(condition,threshold) in rules.items():
            count = self.db.execute('SELECT count(*) FROM events WHERE timestamp>=? AND '+condition, (now-300,)).fetchone()[0]
            active = count >= threshold
            rows.append(f'hybrid_security_alert{{rule="{name}"}} {int(active)}')
            if active:
                cursor=self.db.execute('INSERT OR IGNORE INTO alerts VALUES(?,?,?)',(name,int(now//300),count))
                if cursor.rowcount: print(json.dumps({'event':'SECURITY_ALERT','rule':name,'count':count}),flush=True)
        self.db.commit()
        return '\n'.join(rows)+'\n'


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source',default='logs/security-audit'); parser.add_argument('--database',default='logs/audit-collector.sqlite3')
    parser.add_argument('--bind',default='127.0.0.1'); parser.add_argument('--port',type=int,default=8710)
    args=parser.parse_args();Path(args.database).parent.mkdir(parents=True,exist_ok=True)
    collector=Collector(args.source,args.database)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_GET(self):
            if self.path not in ('/metrics','/health'): self.send_error(404);return
            result=(collector.metrics() if self.path=='/metrics' else 'UP\n').encode()
            self.send_response(200);self.send_header('Content-Type','text/plain');self.send_header('Content-Length',str(len(result)));self.end_headers();self.wfile.write(result)
    server=HTTPServer((args.bind,args.port),Handler);server.timeout=1
    while True:
        collector.collect(); collector.metrics(); server.handle_request()

if __name__=='__main__': main()
