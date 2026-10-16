# Eşik değerleri
WINDOW_SECONDS = 10          # Sliding window süresi
REQS_PER_IP_THRESHOLD = 50   # Bu sürede bir IP'den max istek
TOTAL_RPS_THRESHOLD = 200    # Tüm IP'lerden saniyede max toplam istek

# API
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
THREATFOX_CACHE_TTL = 3600   # Saniye — aynı IP 1 saat boyunca yeniden sorgulanmaz

# GeoIP
GEOIP_DB_PATH = "GeoLite2-City.mmdb"  # MaxMind GeoLite2 dosyası

# Dosya yolları
WHITELIST_PATH = "config/whitelist.txt"
BLACKLIST_PATH = "config/blacklist.txt"
SESSIONS_DIR = "sessions/"

# Ekran yenileme
DASHBOARD_REFRESH_HZ = 2     # Saniyede 2 kez güncelle
