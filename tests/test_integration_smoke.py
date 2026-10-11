"""End-to-end smoke: start honeypot, probe ports, get a report, exit cleanly."""

from __future__ import annotations

import socket
import threading
import time

import pytest

from cybertrap.analyzer import AIAnalyzer
from cybertrap.config import Settings
from cybertrap.listener import HoneypotListener
from cybertrap.logger import EventLogger


pytestmark = pytest.mark.timeout(45)


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_probe_then_analyze_pipeline():
    ssh_port = _free_port()
    http_port = _free_port()
    settings = Settings(
        host="127.0.0.1",
        ssh_port=ssh_port,
        http_port=http_port,
        bind_ports=[ssh_port, http_port],
        analyze_interval_sec=0.5,
        tarpit_delay_sec=0.01,
        max_tarpit_rounds=2,
        connection_timeout_sec=1.5,
        skip_llm_if_unavailable=True,
        llm_cooldown_sec=0.0,
    )
    logger = EventLogger()
    analyzer = AIAnalyzer(settings, logger)
    analyzer._ollama_available = False
    listener = HoneypotListener(settings, logger)
    listener.start()
    analyzer.start()
    try:
        for _ in range(2):
            with socket.create_connection(("127.0.0.1", ssh_port), timeout=2) as sock:
                sock.settimeout(1)
                try:
                    sock.recv(128)
                except socket.timeout:
                    pass
                sock.sendall(b"admin\n")
            time.sleep(0.05)

        with socket.create_connection(("127.0.0.1", http_port), timeout=2) as sock:
            sock.sendall(b"GET /wp-login.php HTTP/1.1\r\nHost: test\r\n\r\n")
            sock.settimeout(1)
            try:
                sock.recv(256)
            except socket.timeout:
                pass

        deadline = time.time() + 8
        reports = []
        while time.time() < deadline:
            reports = analyzer.recent_reports()
            if reports:
                break
            time.sleep(0.2)

        assert logger.total_captured >= 2
        assert reports, "expected at least one analysis report"
        assert reports[-1].source_ips
    finally:
        analyzer.stop(join_timeout=2.0)
        listener.stop(join_timeout=2.0)
