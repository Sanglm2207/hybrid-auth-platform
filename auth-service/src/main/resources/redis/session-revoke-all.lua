local generation = redis.call('INCR', KEYS[1])
redis.call('DEL', KEYS[2])
return generation
