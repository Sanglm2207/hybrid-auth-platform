-- KEYS: family, session, generation. ARGV: owner, expected generation, now millis.
if (redis.call('GET', KEYS[3]) or '0') ~= ARGV[2] then return 0 end
local current = redis.call('GET', KEYS[1]); local ttl = redis.call('PTTL', KEYS[1]); local data = redis.call('GET', KEYS[2])
if not current or current == 'revoked' or ttl <= 0 or not data then return 0 end
local metadata = cjson.decode(data)
if metadata.userId ~= ARGV[1] or tostring(metadata.generation) ~= ARGV[2] or tostring(metadata.credentialRevision) ~= ARGV[4] then return 0 end
metadata.lastActivity = tonumber(ARGV[3])
redis.call('SET', KEYS[2], cjson.encode(metadata), 'PX', ttl)
return 1
