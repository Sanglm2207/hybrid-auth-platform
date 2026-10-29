-- KEYS: token, family, user generation. ARGV: generation, metadata, ttl seconds, token hash.
if (redis.call('GET', KEYS[3]) or '0') ~= ARGV[1] then return 0 end
if redis.call('EXISTS', KEYS[1], KEYS[2]) > 0 then return 0 end
redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3])
redis.call('SET', KEYS[2], ARGV[4], 'EX', ARGV[3])
return 1
