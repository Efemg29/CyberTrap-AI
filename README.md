# CyberTrap-AI

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Ollama](https://img.shields.io/badge/Local_AI-Ollama-orange)
![Cybersecurity](https://img.shields.io/badge/Domain-Cybersecurity-red)
![License](https://img.shields.io/badge/License-MIT-green)

CyberTrap-AI is a local-LLM honeypot that attracts scanners with fake SSH/HTTP services, logs interactions, and turns raw events into human-readable threat reports via Ollama — no cloud APIs required.

## Features

- **Fake services (honeypot):** tarpit-style SSH and HTTP listeners
- **Real-time capture:** connection metadata + bounded payload logging
- **Local LLM (Ollama):** optional LangChain-friendly Ollama analysis (`llama3`, `mistral`, …)
- **Heuristic fallback:** still useful when Ollama is offline
- **Loop-safe design:** timeouts, concurrency caps, queue bounds, clean shutdown

## Architecture

1. **Listener** — binds configured ports and tarpits clients (bounded rounds)
2. **Logger** — thread-safe bounded event queue with TTL pruning
3. **AI Analyzer** — batches pending events; calls Ollama with timeout/cooldown
4. **CLI Dashboard** — rich colored alerts and reports

## Requirements

- Python 3.10+
- [Ollama](https://ollama.com/) (optional but recommended)
- GPU with ~8GB+ VRAM recommended for larger models
- Works on Windows, Linux, and macOS (privileged ports need admin/root)

## Install

```bash
git clone https://github.com/<YOUR_USER>/CyberTrap-AI.git
cd CyberTrap-AI
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
# source .venv/bin/activate
pip install -r requirements.txt
ollama pull llama3
```

## Usage

Default ports are **2222** (SSH) and **8080** (HTTP) so you can test without root/admin:

```bash
python main.py --interface eth0 --model llama3
```

Classic privileged ports (Linux/macOS):

```bash
sudo python main.py --interface eth0 --model llama3 --ssh-port 22 --http-port 80
```

Useful flags:

| Flag | Meaning |
|------|---------|
| `--no-llm` | Heuristic-only analysis |
| `--max-runtime 30` | Auto-exit after N seconds (tests / demos) |
| `--ssh-port` / `--http-port` | Bind ports |
| `--analyze-interval 10` | Seconds between AI batches |

### Example output

```text
[+] Honeypot aktif. 2222 ve 8080 portları dinleniyor...
[!] Şüpheli bağlantı yakalandı: 192.168.1.45 -> Port 2222
[*] LLM Analiz Ediyor...
--- YAPAY ZEKA RAPORU ---
Saldırı Tipi: SSH Brute-Force Denemesi
Detaylar: ...
Tavsiye: 192.168.1.45 IP adresini güvenlik duvarından engelleyin.
-------------------------
```

## Tests

```bash
pytest -q --timeout=30
```

Tests cover queue bounds, accept-loop shutdown, capacity rejection, LLM retry termination, HTTP/SSH probes, and max-runtime exit.

## Project layout

```text
cybertrap/
  config.py      # limits & defaults
  listener.py    # honeypot sockets
  logger.py      # bounded event store
  analyzer.py    # Ollama + heuristics
  dashboard.py   # Rich CLI
  main.py        # orchestration
main.py          # launcher
tests/           # loop-safety + smoke
```

## Roadmap

- [ ] Web dashboard (Flask/FastAPI)
- [ ] Optional fail2ban integration (defensive)
- [ ] RAG over known CVE descriptions

## Legal

For **education and research on networks you own or are authorized to test**. Unauthorized use is illegal.

---

*Developed by Efe — Eastern Mediterranean University (EMU)*
