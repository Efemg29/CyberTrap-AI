"""Rich CLI dashboard for honeypot events and AI reports."""

from __future__ import annotations

import threading
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from cybertrap.analyzer import ThreatReport
from cybertrap.logger import TrapEvent


class CLIDashboard:
    """Thread-safe colored console printer."""

    def __init__(self) -> None:
        # legacy_windows=False avoids cp1252 crashes on emoji / unicode boxes.
        self.console = Console(legacy_windows=False, soft_wrap=True)
        self._lock = threading.Lock()

    def banner(self, ports: list[int], model: str) -> None:
        with self._lock:
            self.console.print(
                Panel.fit(
                    f"[bold green]CyberTrap-AI[/bold green] aktif\n"
                    f"Dinlenen portlar: [cyan]{', '.join(str(p) for p in ports)}[/cyan]\n"
                    f"LLM model: [magenta]{model}[/magenta]",
                    title="Honeypot",
                    border_style="green",
                )
            )

    def connection_alert(self, event: TrapEvent) -> None:
        with self._lock:
            self.console.print(
                f"[bold yellow][!][/bold yellow] Şüpheli bağlantı yakalandı: "
                f"[white]{event.src_ip}[/white] -> Port [cyan]{event.dst_port}[/cyan] "
                f"([blue]{event.service}[/blue])"
            )

    def analyzing(self) -> None:
        with self._lock:
            self.console.print("[bold blue][*][/bold blue] LLM Analiz Ediyor...")

    def report(self, report: ThreatReport) -> None:
        with self._lock:
            style = "green" if report.used_llm else "yellow"
            tag = "LLM" if report.used_llm else "Heuristik"
            body = Text(report.format_cli())
            self.console.print(Panel(body, title=f"Yapay Zeka Raporu ({tag})", border_style=style))

    def info(self, message: str) -> None:
        with self._lock:
            self.console.print(f"[bold green][+][/bold green] {message}")

    def warn(self, message: str) -> None:
        with self._lock:
            self.console.print(f"[bold red][!][/bold red] {message}")

    def status(self, message: str) -> None:
        with self._lock:
            self.console.print(f"[dim]{message}[/dim]")
