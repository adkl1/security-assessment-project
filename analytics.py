import psutil
import threading
import time
import os
from functools import wraps
def measure_resources(interval=0.05):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            cpu_samples = []
            mem_samples = []
            stop_monitor = False
            process = psutil.Process(os.getpid())

            def monitor():
                while not stop_monitor:
                    cpu = psutil.cpu_percent(interval=None)  # instantaneous CPU %
                    mem = process.memory_info().rss / (1024 * 1024)  # memory in MB
                    cpu_samples.append(cpu)
                    mem_samples.append(mem)
                    time.sleep(interval)

            # Start monitoring in background
            monitor_thread = threading.Thread(target=monitor)
            monitor_thread.start()
            result = func(*args, **kwargs)

            # Stop monitoring
            stop_monitor = True
            monitor_thread.join()

            # Compute averages
            avg_cpu = sum(cpu_samples) / len(cpu_samples) if cpu_samples else 0
            avg_mem = sum(mem_samples) / len(mem_samples) if mem_samples else 0

            return result, avg_cpu, avg_mem

        return wrapper

    return decorator