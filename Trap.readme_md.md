# CyberTrap-AI 🕸️🤖

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Ollama](https://img.shields.io/badge/Local_AI-Ollama-orange)
![Cybersecurity](https://img.shields.io/badge/Domain-Cybersecurity-red)
![License](https://img.shields.io/badge/License-MIT-green)

CyberTrap-AI, ağınıza sızmaya çalışan saldırganları tespit etmek ve bu saldırıları **yerel bir Yapay Zeka (Local LLM)** kullanarak gerçek zamanlı olarak analiz etmek için tasarlanmış akıllı bir Honeypot (Ağ Tuzağı) sistemidir. Bulut tabanlı API'lere ihtiyaç duymadan, tamamen yerel donanımınız (örn. RTX 4060) üzerinde çalışarak maksimum gizlilik ve hız sağlar.

## 🚀 Özellikler

- **Sahte Servisler (Honeypot):** Saldırganları cezbetmek için sahte SSH ve HTTP portları (Tarpit) açar.
- **Gerçek Zamanlı Trafik Analizi:** Gelen bağlantıları, port taramalarını ve payload'ları yakalar.
- **Yerel LLM Entegrasyonu (Ollama):** Yakalanan çiğ logları `Ollama` üzerinden çalışan yerel bir modele (Llama 3, Mistral vb.) göndererek saldırı tipini analiz eder.
- **Akıllı Tehdit Raporlaması:** CLI üzerinden "Bu IP adresi şu wordlist ile SSH brute-force deniyor" gibi insan dilinde, anlaşılır uyarılar üretir.

## 🏗️ Mimari & Çalışma Mantığı

1. **Listener (Dinleyici):** Belirlenen portlarda (örn. 22, 8080) sahte servisler ayağa kalkar.
2. **Logger (Kayıtçı):** Bu servislere gelen her TCP/UDP paketi veya payload kaydedilir.
3. **AI Analyzer (Yapay Zeka Analizörü):** Loglar belirli aralıklarla LangChain/Ollama aracılığıyla yerel modele prompt olarak beslenir.
4. **Dashboard / CLI:** Modelin çıkarttığı anlamlı analiz sonuçları terminale renkli ve yapılandırılmış bir şekilde basılır.

## ⚙️ Gereksinimler

- Python 3.10+
- [Ollama](https://ollama.com/) (Yerel yapay zeka modellerini çalıştırmak için)
- En az 8GB VRAM'e sahip bir GPU (Önerilen: NVIDIA RTX 4060 veya üzeri)
- Linux / macOS ortamı (Windows'ta WSL2 önerilir)

## 🛠️ Kurulum

**1. Repoyu Klonlayın:**
```bash
git clone https://github.com/KULLANICI_ADIN/CyberTrap-AI.git
cd CyberTrap-AI
```

**2. Gerekli Python Kütüphanelerini Kurun:**
```bash
pip install -r requirements.txt
```

**3. Ollama Modelini İndirin (Önerilen: Llama 3 veya Mistral):**
```bash
ollama pull llama3
```

## 💻 Kullanım

Honeypot'u başlatmak için scripti yönetici (root) ayrıcalıklarıyla çalıştırın (Port dinlemek için gereklidir):

```bash
sudo python main.py --interface eth0 --model llama3
```

**Örnek Çıktı:**
```text
[+] Honeypot aktif. 22 ve 80 portları dinleniyor...
[!] Şüpheli bağlantı yakalandı: 192.168.1.45 -> Port 22
[*] LLM Analiz Ediyor...
--- YAPAY ZEKA RAPORU ---
Saldırı Tipi: SSH Brute-Force Denemesi
Detaylar: Saldırgan 'root' ve 'admin' kullanıcı adlarıyla art arda giriş denemesi yapıyor. 
Tavsiye: 192.168.1.45 IP adresini derhal güvenlik duvarından (iptables) engelleyin.
-------------------------
```

## 🗺️ Yol Haritası (Roadmap)

- [ ] Web Tabanlı Dashboard (Flask/FastAPI) eklenmesi.
- [ ] Otonom savunma mekanizması (Saldırganı otomatik olarak fail2ban ile banlama).
- [ ] RAG (Retrieval-Augmented Generation) ile bilinen CVE veri tabanlarının sisteme entegre edilmesi.

## ⚠️ Yasal Uyarı

Bu proje yalnızca **eğitim ve araştırma** amaçlıdır. Kendi ağınızda güvenlik testleri yapmak ve savunma mekanizmalarını anlamak için geliştirilmiştir. Yetkisiz sistemlerde kullanılması yasa dışıdır.

---
*Developed by [Senin Adın/Nickin] - Eastern Mediterranean University (EMU)*