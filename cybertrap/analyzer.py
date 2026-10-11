"""Ollama / LangChain based threat analyzer with cooldown and timeout guards."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import List, Optional

import httpx

from cybertrap.config import Settings
from cybertrap.logger import EventLogger, TrapEvent


@dataclass
class ThreatReport:
    """Human-readable threat analysis produced by the local LLM (or fallback)."""

    attack_type: str
    details: str
    recommendation: str
    source_ips: List[str]
    raw_model_output: str
    used_llm: bool
    created_at: float

    def format_cli(self) -> str:
        ips = ", ".join(self.source_ips) if self.source_ips else "unknown"
        return (
            "--- YAPAY ZEKA RAPORU ---\n"
            f"Saldırı Tipi: {self.attack_type}\n"
            f"Kaynak IP: {ips}\n"
            f"Detaylar: {self.details}\n"
            f"Tavsiye: {self.recommendation}\n"
            "-------------------------"
        )


class AIAnalyzer:
    """
    Periodically drains pending events and asks a local Ollama model to analyze them.

    Safety:
    - Single worker thread with stop Event
    - LLM HTTP timeout + retry cap
    - Cooldown between calls (prevents request storms)
    - Heuristic fallback if Ollama is down
    """

    SYSTEM_PROMPT = (
        "You are a defensive cybersecurity analyst for a honeypot. "
        "Given raw connection logs, identify likely attack type "
        "(e.g. SSH brute-force, HTTP probing, port scan, credential stuffing). "
        "Respond in Turkish with exactly these labeled lines:\n"
        "Saldırı Tipi: ...\n"
        "Detaylar: ...\n"
        "Tavsiye: ...\n"
        "Be concise. Do not invent CVEs. Do not provide offensive exploit steps."
    )

    def __init__(self, settings: Settings, event_logger: EventLogger) -> None:
        self.settings = settings
        self.logger = event_logger
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_llm_call = 0.0
        self._lock = threading.Lock()
        self._reports: List[ThreatReport] = []
        self._ollama_available: Optional[bool] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._analyze_loop,
            name="ai-analyzer",
            daemon=True,
        )
        self._thread.start()

    def stop(self, join_timeout: float = 3.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=join_timeout)
            self._thread = None

    def recent_reports(self, limit: int = 20) -> List[ThreatReport]:
        with self._lock:
            return list(self._reports[-limit:])

    def check_ollama(self) -> bool:
        try:
            with httpx.Client(timeout=3.0) as client:
                r = client.get(f"{self.settings.ollama_base_url}/api/tags")
                ok = r.status_code == 200
        except Exception:
            ok = False
        self._ollama_available = ok
        return ok

    def _analyze_loop(self) -> None:
        """Wake on interval; never busy-spin. Hard stop via Event.wait return."""
        while not self._stop.wait(self.settings.analyze_interval_sec):
            try:
                self.analyze_once()
            except Exception:
                # Swallow unexpected errors so the loop stays alive but controlled.
                time.sleep(0.5)

    def analyze_once(self) -> Optional[ThreatReport]:
        events = self.logger.pending_events(self.settings.max_events_per_batch)
        if not events:
            return None

        report = self._build_report(events)
        self.logger.mark_analyzed([e.event_id for e in events])
        with self._lock:
            self._reports.append(report)
            # Bound report history like the event queue.
            if len(self._reports) > 200:
                self._reports = self._reports[-100:]
        return report

    def _build_report(self, events: List[TrapEvent]) -> ThreatReport:
        ips = sorted({e.src_ip for e in events})
        if self.settings.skip_llm_if_unavailable:
            if self._ollama_available is None:
                self.check_ollama()
        used_llm = False
        raw = ""

        now = time.time()
        can_call = (now - self._last_llm_call) >= self.settings.llm_cooldown_sec
        if can_call and (self._ollama_available or not self.settings.skip_llm_if_unavailable):
            raw = self._call_ollama(events)
            self._last_llm_call = time.time()
            used_llm = bool(raw.strip()) and not raw.startswith("[LLM unavailable")

        if used_llm:
            parsed = self._parse_model_output(raw)
            return ThreatReport(
                attack_type=parsed.get("attack_type", "Bilinmeyen / LLM Çıktısı"),
                details=parsed.get("details", raw[:500]),
                recommendation=parsed.get(
                    "recommendation",
                    f"{', '.join(ips)} IP adreslerini izleyin.",
                ),
                source_ips=ips,
                raw_model_output=raw,
                used_llm=True,
                created_at=time.time(),
            )

        return self._heuristic_report(events, ips)

    def _call_ollama(self, events: List[TrapEvent]) -> str:
        log_blob = "\n".join(e.summary() for e in events)
        prompt = (
            f"{self.SYSTEM_PROMPT}\n\n"
            f"Model: {self.settings.model}\n"
            f"Yakalanan olaylar:\n{log_blob}\n"
        )
        payload = {
            "model": self.settings.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.2, "num_predict": 256},
        }
        attempts = 0
        last_err = ""
        while attempts <= self.settings.llm_max_retries:
            attempts += 1
            try:
                with httpx.Client(timeout=self.settings.llm_timeout_sec) as client:
                    r = client.post(
                        f"{self.settings.ollama_base_url}/api/generate",
                        json=payload,
                    )
                    if r.status_code == 200:
                        data = r.json()
                        text = data.get("response", "")
                        self._ollama_available = True
                        return text
                    last_err = f"HTTP {r.status_code}"
            except Exception as exc:
                last_err = str(exc)
                self._ollama_available = False
            # Tiny backoff; capped by retry count so this cannot loop forever.
            time.sleep(min(1.0 * attempts, 2.0))
        return f"[LLM unavailable: {last_err}]"

    @staticmethod
    def _parse_model_output(text: str) -> dict:
        result = {}
        for line in text.splitlines():
            lower = line.lower()
            if lower.startswith("saldırı tipi:") or lower.startswith("saldiri tipi:"):
                result["attack_type"] = line.split(":", 1)[1].strip()
            elif lower.startswith("detaylar:"):
                result["details"] = line.split(":", 1)[1].strip()
            elif lower.startswith("tavsiye:"):
                result["recommendation"] = line.split(":", 1)[1].strip()
        return result

    @staticmethod
    def _heuristic_report(events: List[TrapEvent], ips: List[str]) -> ThreatReport:
        services = {e.service for e in events}
        payloads = " ".join(e.payload.lower() for e in events)
        ssh_hits = sum(1 for e in events if e.service == "ssh")
        http_hits = sum(1 for e in events if e.service == "http")

        if "ssh" in services and ssh_hits >= 2:
            attack = "SSH Brute-Force Denemesi"
            details = (
                f"Saldırgan(lar) {ssh_hits} SSH bağlantısı açtı. "
                "Banner etkileşimi ve tekrarlayan oturumlar brute-force izlenimi veriyor."
            )
        elif "http" in services and any(
            k in payloads for k in ("admin", "login", "wp-", ".env", "phpmyadmin")
        ):
            attack = "HTTP Yönetim Paneli / Web Probe"
            details = (
                f"{http_hits} HTTP isteği yakalandı; payload içinde yönetim paneli "
                "veya hassas yol izleri görülüyor."
            )
        elif "http" in services:
            attack = "HTTP Keşif / Tarama"
            details = f"{http_hits} HTTP bağlantısı honeypot'a düştü."
        else:
            attack = "Şüpheli TCP Etkileşimi"
            details = f"{len(events)} olay kaydedildi; servisler: {', '.join(sorted(services)) or 'bilinmiyor'}."

        ip_list = ", ".join(ips) if ips else "bilinmeyen"
        return ThreatReport(
            attack_type=attack,
            details=details,
            recommendation=(
                f"{ip_list} IP adresini güvenlik duvarından engellemeyi "
                "ve fail2ban ile izlemeyi düşünün."
            ),
            source_ips=ips,
            raw_model_output="",
            used_llm=False,
            created_at=time.time(),
        )
