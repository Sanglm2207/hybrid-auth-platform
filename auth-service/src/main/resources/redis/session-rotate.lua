-- KEYS: old token, new token, family, user generation.
-- ARGV: metadata, expected generation, old hash, new hash.
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
if (redis.call('GET', KEYS[4]) or '0') ~= ARGV[2] then return 0 end
local current = redis.call('GET', KEYS[3])
local ttl = redis.call('PTTL', KEYS[3])
if not current or ttl <= 0 or current == 'revoked' then return 0 end
if current ~= ARGV[3] then
  redis.call('SET', KEYS[3], 'revoked', 'PX', ttl)
  return -1
end
if redis.call('EXISTS', KEYS[2]) > 0 then return 0 end
-- Old records remain as tombstones, bounded by this family's absolute expiry.
redis.call('SET', KEYS[2], ARGV[1], 'PX', ttl)
redis.call('SET', KEYS[3], ARGV[4], 'PX', ttl)
return 1
