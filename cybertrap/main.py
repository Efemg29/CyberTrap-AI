"""CyberTrap-AI entrypoint: start listeners, analyzer, and CLI loop."""

from __future__ import annotations

import argparse
import signal
import sys
import time
from typing import Optional

from cybertrap.analyzer import AIAnalyzer
from cybertrap.config import Settings
from cybertrap.dashboard import CLIDashboard
from cybertrap.listener import HoneypotListener
from cybertrap.logger import EventLogger


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cybertrap",
        description="CyberTrap-AI — local LLM honeypot for defensive research",
    )
    p.add_argument("--interface", default="eth0", help="Network interface label (informational)")
    p.add_argument("--host", default="0.0.0.0", help="Bind address")
    p.add_argument("--model", default="llama3", help="Ollama model name")
    p.add_argument("--ssh-port", type=int, default=2222, help="Fake SSH listen port")
    p.add_argument("--http-port", type=int, default=8080, help="Fake HTTP listen port")
    p.add_argument(
        "--analyze-interval",
        type=float,
        default=15.0,
        help="Seconds between AI analysis batches",
    )
    p.add_argument(
        "--max-runtime",
        type=float,
        default=None,
        help="Optional hard stop after N seconds (useful for tests)",
    )
    p.add_argument(
        "--no-llm",
        action="store_true",
        help="Force heuristic-only analysis (skip Ollama)",
    )
    p.add_argument(
        "--ollama-url",
        default="http://127.0.0.1:11434",
        help="Ollama base URL",
    )
    return p


def settings_from_args(args: argparse.Namespace) -> Settings:
    return Settings(
        host=args.host,
        interface=args.interface,
        model=args.model,
        ollama_base_url=args.ollama_url,
        ssh_port=args.ssh_port,
        http_port=args.http_port,
        analyze_interval_sec=max(1.0, args.analyze_interval),
        max_runtime_sec=args.max_runtime,
        skip_llm_if_unavailable=True,
        bind_ports=[args.ssh_port, args.http_port],
    )


class CyberTrapApp:
    """Orchestrates components with a non-busy main loop and clean shutdown."""

    def __init__(self, settings: Settings, force_no_llm: bool = False) -> None:
        self.settings = settings
        self.force_no_llm = force_no_llm
        self.dashboard = CLIDashboard()
        self.logger = EventLogger(
            max_queue_size=settings.max_queue_size,
            event_ttl_sec=settings.event_ttl_sec,
        )
        self.analyzer = AIAnalyzer(settings, self.logger)
        self.listener = HoneypotListener(
            settings,
            self.logger,
            on_event=self.dashboard.connection_alert,
        )
        self._stop = False
        self._last_report_count = 0

    def _install_signals(self) -> None:
        def _handler(signum, frame) -> None:  # noqa: ARG001
            self._stop = True
            self.dashboard.warn("Kapatma sinyali alındı, güvenli çıkış yapılıyor...")

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, _handler)
            except (ValueError, OSError):
                # Signals may be unavailable in some threads / platforms.
                pass

    def start(self) -> None:
        self._install_signals()
        self.dashboard.banner(self.settings.bind_ports, self.settings.model)
        self.dashboard.info(
            f"Honeypot aktif. {self.settings.ssh_port} ve {self.settings.http_port} "
            f"portları dinleniyor... (interface={self.settings.interface})"
        )

        if self.force_no_llm:
            self.settings.skip_llm_if_unavailable = True
            self.analyzer._ollama_available = False  # noqa: SLF001 — intentional test hook
            self.dashboard.warn("LLM devre dışı (--no-llm). Heuristik raporlama kullanılacak.")
        else:
            if self.analyzer.check_ollama():
                self.dashboard.info(f"Ollama erişilebilir ({self.settings.ollama_base_url})")
            else:
                self.dashboard.warn(
                    "Ollama erişilemiyor; heuristik analiz ile devam edilecek. "
                    "Ollama açıldığında LLM otomatik denenecek."
                )

        try:
            self.listener.start()
        except OSError as exc:
            self.dashboard.warn(f"Port dinlenemedi: {exc}")
            self.dashboard.warn(
                "İpucu: yönetici yetkisi veya boş portlar deneyin "
                "(örn. --ssh-port 2222 --http-port 8080)."
            )
            raise

        self.analyzer.start()
        self._main_loop()

    def _main_loop(self) -> None:
        """
        Main loop wakes on tick; never busy-spins.
        Hard-capped by optional max_runtime_sec for automated tests.
        """
        started = time.time()
        tick = max(0.1, self.settings.main_loop_tick_sec)
        # Absolute iteration ceiling as belt-and-suspenders against runaway loops.
        max_iters = None
        if self.settings.max_runtime_sec is not None:
            max_iters = int(self.settings.max_runtime_sec / tick) + 5

        iterations = 0
        while not self._stop:
            iterations += 1
            if max_iters is not None and iterations > max_iters:
                self.dashboard.warn("max_runtime / max_iters tavanına ulaşıldı, çıkılıyor.")
                break
            if (
                self.settings.max_runtime_sec is not None
                and (time.time() - started) >= self.settings.max_runtime_sec
            ):
                self.dashboard.info("Maksimum çalışma süresi doldu, kapatılıyor.")
                break

            reports = self.analyzer.recent_reports()
            if len(reports) > self._last_report_count:
                for report in reports[self._last_report_count :]:
                    if report.used_llm:
                        self.dashboard.analyzing()
                    self.dashboard.report(report)
                self._last_report_count = len(reports)

            time.sleep(tick)

        self.shutdown()

    def shutdown(self) -> None:
        self.listener.stop()
        self.analyzer.stop()
        stats = self.logger.stats()
        self.dashboard.info(
            f"Durduruldu. Yakalanan olay: {stats['total_captured']} "
            f"(bellekte: {stats['stored']})"
        )


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    settings = settings_from_args(args)
    # If user asked for LLM skip, keep analyzer from calling Ollama.
    if args.no_llm:
        settings.llm_max_retries = 0

    app = CyberTrapApp(settings, force_no_llm=args.no_llm)
    try:
        app.start()
    except OSError:
        return 1
    except KeyboardInterrupt:
        app.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
