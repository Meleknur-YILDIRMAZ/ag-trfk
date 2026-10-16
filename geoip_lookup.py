import geoip2.database
import os
import requests

class GeoIPLookup:
    def __init__(self, db_path):
        self.db_path = db_path
        self.reader = None
        self.cache = {}
        
        if os.path.exists(self.db_path):
            try:
                self.reader = geoip2.database.Reader(self.db_path)
            except Exception:
                self.reader = None

    def lookup(self, ip):
        if ip in self.cache:
            return self.cache[ip]

        # Local IP check
        if any(ip.startswith(prefix) for prefix in ["10.", "192.168.", "172.16.", "127.", "169.254."]):
            return {"country": "LOCAL", "city": "LOCAL", "asn": "LOCAL", "flag": "🏠"}

        # Try local reader first
        if self.reader:
            try:
                response = self.reader.city(ip)
                result = {
                    "country": response.country.name or "UNKNOWN",
                    "city": response.city.name or "UNKNOWN",
                    "asn": "N/A",
                    "flag": self._get_flag(response.country.iso_code)
                }
                self.cache[ip] = result
                return result
            except Exception:
                pass

        # API Fallback (ip-api.com)
        try:
            # Note: Free API has a limit of 45 requests per minute
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
            if response.get("status") == "success":
                result = {
                    "country": response.get("country", "UNKNOWN"),
                    "city": response.get("city", "UNKNOWN"),
                    "asn": response.get("as", "UNKNOWN"),
                    "flag": self._get_flag(response.get("countryCode"))
                }
                self.cache[ip] = result
                return result
        except Exception:
            pass

        return {"country": "UNKNOWN", "city": "UNKNOWN", "asn": "UNKNOWN", "flag": "❓"}

    def _get_flag(self, country_code):
        if not country_code:
            return "❓"
        # Convert country code to emoji flag
        try:
            OFFSET = 127397
            return "".join(chr(ord(c) + OFFSET) for c in country_code.upper())
        except Exception:
            return "❓"

    def close(self):
        if self.reader:
            self.reader.close()
