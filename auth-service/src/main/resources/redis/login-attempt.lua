-- KEYS: failure counter, temporary lock. ARGV: operation, threshold, observation ms, lock ms.
local ttl = redis.call('PTTL', KEYS[2])
if ttl > 0 then return ttl end
if ARGV[1] == 'check' then return 0 end
if ARGV[1] == 'success' then redis.call('DEL', KEYS[1]); return 0 end
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[3]) end
if count >= tonumber(ARGV[2]) then
  redis.call('DEL', KEYS[1])
  redis.call('SET', KEYS[2], '1', 'PX', ARGV[4])
  return tonumber(ARGV[4])
end
return 0
