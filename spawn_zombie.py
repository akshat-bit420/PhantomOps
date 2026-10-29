import os
import time

pid = os.getpid()
print(f"👻 Spawning a real runaway Zombie Process on Windows!")
print(f"🎯 Target PID: {pid}")
print("Holding ~700 MB of real RAM in an infinite loop... Try finding and killing this PID in PhantomOps!")

# Allocate ~700 MB of real RAM so it becomes an obvious live memory anomaly
zombie_memory_block = bytearray(700 * 1024 * 1024)

try:
    while True:
        # Slight CPU burn
        _ = sum(x * x for x in range(2000))
        time.sleep(0.1)
except KeyboardInterrupt:
    print("Zombie stopped manually.")