-- KEYS: family, session, user index, generation. ARGV: owner, family ID.
local data = redis.call('GET', KEYS[2])
if not data then return 0 end
local metadata = cjson.decode(data)
if metadata.userId ~= ARGV[1] or tostring(metadata.generation) ~= (redis.call('GET', KEYS[4]) or '0') then return 0 end
local current = redis.call('GET', KEYS[1]); local ttl = redis.call('PTTL', KEYS[1])
if not current or current == 'revoked' or ttl <= 0 then return 0 end
redis.call('SET', KEYS[1], 'revoked', 'PX', ttl)
redis.call('ZREM', KEYS[3], ARGV[2])
return 1
