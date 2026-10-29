-- KEYS: old token, new token, family, generation, session metadata, user index.
-- ARGV: token metadata, expected generation, old hash, new hash, now millis, IP, user agent, family ID.
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
if (redis.call('GET', KEYS[4]) or '0') ~= ARGV[2] then return 0 end
local current = redis.call('GET', KEYS[3])
local ttl = redis.call('PTTL', KEYS[3])
local data = redis.call('GET', KEYS[5])
if not current or ttl <= 0 or current == 'revoked' or not data then return 0 end
if current ~= ARGV[3] then
  redis.call('SET', KEYS[3], 'revoked', 'PX', ttl)
  redis.call('ZREM', KEYS[6], ARGV[8])
  return -1
end
if redis.call('EXISTS', KEYS[2]) > 0 then return 0 end
local metadata = cjson.decode(data)
metadata.lastActivity = tonumber(ARGV[5]); metadata.ip = ARGV[6]; metadata.userAgent = ARGV[7]
redis.call('SET', KEYS[2], ARGV[1], 'PX', ttl)
redis.call('SET', KEYS[3], ARGV[4], 'PX', ttl)
redis.call('SET', KEYS[5], cjson.encode(metadata), 'PX', ttl)
return 1
