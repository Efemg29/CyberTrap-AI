# CyberTrap-AI

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Ollama](https://img.shields.io/badge/Local_AI-Ollama-orange)
![Cybersecurity](https://img.shields.io/badge/Domain-Cybersecurity-red)
![License](https://img.shields.io/badge/License-MIT-green)

CyberTrap-AI is a local LLM honeypot that attracts scanners with fake SSH and HTTP services, logs interactions, and turns raw events into human-readable threat reports via Ollama. No cloud APIs are required.

## Features

- **Fake services (honeypot):** tarpit-style SSH and HTTP listeners
- **Real-time capture:** connection metadata and bounded payload logging
- **Local LLM (Ollama):** optional analysis with models such as `llama3` or `mistral`
- **Heuristic fallback:** still useful when Ollama is offline
- **Loop-safe design:** timeouts, concurrency caps, queue bounds, and clean shutdown

## Architecture

1. **Listener** — binds configured ports and tarpits clients (bounded rounds)
2. **Logger** — thread-safe bounded event queue with TTL pruning
3. **AI Analyzer** — batches pending events and calls Ollama with timeout and cooldown
4. **CLI Dashboard** — colored terminal alerts and reports

## Requirements

- Python 3.10+
- [Ollama](https://ollama.com/) (optional but recommended)
- GPU with about 8GB+ VRAM recommended for larger models
- Works on Windows, Linux, and macOS (privileged ports need admin/root)

## Install

```bash
git clone https://github.com/Efemg29/CyberTrap-AI.git
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

Default ports are **2222** (SSH) and **8080** (HTTP) so you can test without root or admin:

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
[+] Honeypot active. Listening on ports 2222 and 8080...
[!] Suspicious connection captured: 192.168.1.45 -> Port 2222
[*] LLM analyzing...
--- AI REPORT ---
Attack type: SSH brute-force attempt
Details: The attacker is trying repeated logins with usernames such as root and admin.
Recommendation: Block 192.168.1.45 at the firewall immediately.
-----------------
```

## Tests

```bash
pytest -q --timeout=30
```

Tests cover queue bounds, accept-loop shutdown, capacity rejection, LLM retry termination, HTTP/SSH probes, and max-runtime exit.

## Project layout

```text
cybertrap/
  config.py      # limits and defaults
  listener.py    # honeypot sockets
  logger.py      # bounded event store
  analyzer.py    # Ollama and heuristics
  dashboard.py   # Rich CLI
  main.py        # orchestration
main.py          # launcher
tests/           # loop-safety and smoke tests
```

## Roadmap

- [ ] Web dashboard (Flask/FastAPI)
- [ ] Optional fail2ban integration (defensive)
- [ ] RAG over known CVE descriptions

## Legal

For education and research on networks you own or are authorized to test. Unauthorized use is illegal.

---

Developed by Efe — Eastern Mediterranean University (EMU)
