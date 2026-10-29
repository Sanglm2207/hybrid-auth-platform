-- SQL is authoritative. Cached generations may be reconciled only while the SQL user lock is held.
redis.call('SET', KEYS[1], ARGV[1])
return 1
