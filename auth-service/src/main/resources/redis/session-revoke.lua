-- KEYS: token, family. ARGV: expected metadata.
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
local ttl = redis.call('PTTL', KEYS[2])
if ttl <= 0 then return 0 end
redis.call('SET', KEYS[2], 'revoked', 'PX', ttl)
return 1
