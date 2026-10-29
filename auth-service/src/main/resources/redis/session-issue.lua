-- KEYS: token, family, generation, session metadata, user session index, last issuing credential revision.
-- ARGV: generation, token metadata, ttl seconds, hash, session JSON, family ID, now millis.
if (redis.call('GET', KEYS[3]) or '0') ~= ARGV[1] then return 0 end
-- A credential revision changed outside normal revocation (e.g. explicit admin bootstrap).
-- Clear obsolete index entries before applying the active-session cap.
if redis.call('GET', KEYS[6]) ~= ARGV[8] then
  redis.call('DEL', KEYS[5])
  redis.call('SET', KEYS[6], ARGV[8])
end
redis.call('ZREMRANGEBYSCORE', KEYS[5], '-inf', ARGV[7])
if ARGV[9] ~= 'sql' and redis.call('ZCARD', KEYS[5]) >= 100 then return -2 end
if redis.call('EXISTS', KEYS[1], KEYS[2]) > 0 then return 0 end
redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3])
redis.call('SET', KEYS[2], ARGV[4], 'EX', ARGV[3])
redis.call('SET', KEYS[4], ARGV[5], 'EX', ARGV[3])
redis.call('ZADD', KEYS[5], tonumber(ARGV[7]) + tonumber(ARGV[3])*1000, ARGV[6])
redis.call('EXPIRE', KEYS[5], ARGV[3])
return 1
