# 🛡️ WARD — Ağ Trafik Analizörü & Saldırı Tespit Sistemi (IDS / IPS)

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali%20%7C%20WSL2-red?logo=kalilinux&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-Packet%20Sniffing-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

**WARD (Web & Attack Response Dashboard)**, ağ trafiğini gerçek zamanlı olarak dinleyen, şüpheli aktiviteleri ve siber saldırı girişimlerini tespit eden, tehdit istihbaratı (Threat Intelligence) sorgulaması yapan ve `iptables` entegrasyonu ile saldırgan IP adreslerini anında engelleyebilen terminal tabanlı (TUI) bir **Saldırı Tespit ve Önleme Sistemidir (IDS/IPS)**.

---

## ✨ Temel Özellikler

* **📡 Gerçek Zamanlı Paket Yakalama (`Scapy`):** Seçilen ağ arayüzündeki (`eth0`, `wlan0`, `lo` vb.) TCP, UDP ve ICMP paketlerini canlı olarak yakalar ve analiz eder.
* **🔓 Şifresiz HTTP Trafik Tespiti (`HTTP_CLEARTEXT`):** Port 80 üzerinden geçen şifrelenmemiş HTTP isteklerini (`GET`, `POST`, `PUT`, `DELETE`, `HEAD`) ve `Host` başlıklarını yakalayarak yüksek öncelikli uyarı üretir.
* **🌊 DDoS & Flood Saldırı Tespiti (`POTENTIAL_DDOS`):** Kayan pencere (*Sliding Window*) algoritması kullanarak hem IP bazlı istek limitlerini hem de toplam saniye başı paket oranını (RPS) gerçek zamanlı denetler. Kara listedeki IP'ler için otomatik olarak daha hassas eşik değeri uygular.
* **🕵️‍♂️ Tehdit İstihbaratı Entegrasyonu (`ThreatFox API`):** Ağınıza bağlanan dış IP adreslerini asenkron olarak **abuse.ch ThreatFox** veritabanında sorgular; bilinen Botnet, C2 veya Malware sunucularıyla eşleşen IP'ler için `CRITICAL` seviyesinde alarm üretir.
* **🌍 GeoIP Konum ve Ülke Bayrağı Tespiti:** MaxMind `GeoLite2-City.mmdb` veritabanı veya `ip-api.com` yedeklemesi (fallback) ile saldırgan IP'lerin ülke, şehir ve ASN bilgilerini ülke bayraklarıyla birlikte gösterir.
* **🔥 Gerçek Zamanlı Güvenlik Duvarı (`iptables` IPS):** Tek tuşla saldırgan IP adreslerini Linux çekirdeği (`iptables -j DROP`) seviyesinde anında engeller ve oturum sonunda kuralları temizler.
* **📊 Canlı Terminal Arayüzü (`Rich` TUI) & Oturum Kayıtları:** Canlı paket akışı, son alarmlar, ağ istatistikleri ve oturum sonunda otomatik oluşturulan `alerts.jsonl`, `packets.csv` ve `summary.txt` raporları.

---

## 🏗️ Sistem Mimarisi

```
ag-trfk/
├── main.py                # Ana uygulama döngüsü, thread yönetimi ve klavye kısayolları
├── packet_capture.py      # Scapy tabanlı asenkron paket dinleme modülü
├── traffic_analyzer.py    # Sliding Window (RPS) analizi ve HTTP payload ayrıştırıcı
├── detection_engine.py    # HTTPDetector, DDoSDetector ve MaliciousIPDetector (ThreatFox)
├── firewall_manager.py    # Linux iptables üzerinden aktif IP engelleme / engel kaldırma
├── alert_system.py        # JSONL alarm kaydı, CSV paket loglama ve oturum özeti
├── geoip_lookup.py        # GeoLite2 veritabanı ve IP-API tabanlı coğrafi konum tespiti
├── dashboard.py           # Rich kütüphanesi ile hazırlanan canlı TUI kontrol paneli
├── list_manager.py        # Whitelist (Beyaz Liste) ve Blacklist (Kara Liste) yönetimi
├── ip_cache.py            # API sorgularını optimize eden TTL destekli önbellek
└── config/
    ├── settings.py        # Eşik değerleri, zaman pencereleri ve API yapılandırması
    ├── whitelist.txt      # Güvenilir IP listesi
    └── blacklist.txt      # Yasaklı IP listesi
```

---

## 🚀 Kurulum ve Çalıştırma

Ham ağ paketlerini (Raw Sockets) dinlemek ve `iptables` kurallarını yönetebilmek için uygulamanın **Linux (Kali, Ubuntu veya WSL2)** ortamında `root` (`sudo`) yetkisiyle çalıştırılması gerekir.

### 1. Projeyi Klonlayın
```bash
git clone https://github.com/Meleknur-YILDIRMAZ/ag-trfk.git
cd ag-trfk
```

### 2. Bağımlılıkları Yükleyin
```bash
pip install -r requirements.txt
```

### 3. Uygulamayı Başlatın
```bash
sudo python3 main.py
```
Açılışta dinlemek istediğiniz ağ arayüzünü (örneğin `eth0`) seçerek canlı kontrol panelini başlatabilirsiniz.

---

## ⌨️ Kontrol Paneli Kısayolları

Canlı dashboard ekranı açıkken aşağıdaki klavye kısayolları ile sisteme anlık müdahale edebilirsiniz:

| Tuş | İşlev | Açıklama |
| :---: | :--- | :--- |
| **`[W]`** | **Whitelist** | Girilen IP adresini güvenilir listeye ekler (`config/whitelist.txt`). |
| **`[B]`** | **Blacklist** | Girilen IP adresini kara listeye ekler ve DDoS eşiğini düşürür (`config/blacklist.txt`). |
| **`[X]`** | **Block IP** | Girilen IP adresini `iptables` üzerinden gerçek zamanlı olarak engeller (`DROP`). |
| **`[U]`** | **Unblock IP** | Güvenlik duvarından engellenmiş bir IP adresinin engelini kaldırır. |
| **`[Q]`** | **Exit** | Oturumu güvenli şekilde sonlandırır, güvenlik duvarı kurallarını temizler ve raporları kaydeder. |

---

## 🧪 Saldırı Senaryolarını Test Etme

Uygulama `eth0` arayüzünde çalışırken farklı bir terminal penceresinden aşağıdaki testleri uygulayabilirsiniz:

1. **Şifresiz HTTP Trafiği Testi (`HTTP_CLEARTEXT`):**
   ```bash
   curl -s http://neverssl.com > /dev/null
   ```
2. **Kara Liste Eşleşme Testi (`BLACKLIST_MATCH`):**
   Dashboard'da `b` tuşuna basıp `1.1.1.1` ekledikten sonra:
   ```bash
   ping -c 3 1.1.1.1
   ```
3. **DDoS / Yoğun İstek Testi (`POTENTIAL_DDOS`):**
   ```bash
   for i in {1..60}; do curl -s -m 1 http://example.com > /dev/null & done
   ```
4. **Aktif Güvenlik Duvarı Engelleme Testi (`iptables`):**
   Dashboard'da `x` tuşuna basıp `8.8.8.8` adresini engelledikten sonra:
   ```bash
   ping -c 3 8.8.8.8  # %100 Packet Loss gözlemlenir
   ```

---

## 📁 Oturum Logları ve Raporlama

Uygulamadan `q` tuşu ile çıkıldığında `sessions/session_YYYYMMDD_HHMMSS/` klasörü altında 3 farklı rapor dosyası otomatik olarak üretilir:
* **`alerts.jsonl`:** Tespit edilen tüm saldırıların zaman damgası, önem derecesi, kaynak/hedef IP ve GeoIP bilgileri.
* **`packets.csv`:** Oturum boyunca yakalanan tüm ağ paketlerinin CSV dökümü.
* **`summary.txt`:** Oturum süresi, toplam paket sayısı, alarm dağılımı ve en çok trafik üreten ilk 5 IP adresinin özeti.

---

## 👩‍💻 Geliştirici

**Meleknur YILDIRMAZ**  
*Siber Güvenlik & Ağ Trafik Analizi Projesi*
