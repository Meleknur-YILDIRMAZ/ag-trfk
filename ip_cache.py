import time
import threading

class IPCache:
    def __init__(self, ttl):
        self.ttl = ttl
        self.cache = {}
        self.lock = threading.Lock()

    def get(self, ip):
        with self.lock:
            if ip in self.cache:
                data, timestamp = self.cache[ip]
                if time.time() - timestamp < self.ttl:
                    return data
                else:
                    del self.cache[ip]
            return None

    def set(self, ip, result):
        with self.lock:
            self.cache[ip] = (result, time.time())
