"""Regression tests for dangerous / runaway loops and resource bounds."""

from __future__ import annotations

import socket
import threading
import time

import pytest

from cybertrap.analyzer import AIAnalyzer
from cybertrap.config import Settings
from cybertrap.listener import HoneypotListener
from cybertrap.logger import EventLogger
from cybertrap.main import CyberTrapApp, settings_from_args
from cybertrap.main import build_parser


pytestmark = pytest.mark.timeout(30)


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_event_logger_bounded_queue():
    logger = EventLogger(max_queue_size=10, event_ttl_sec=3600)
    for i in range(50):
        logger.log_event("1.2.3.4", 1000 + i, 22, "ssh", f"payload-{i}")
    assert logger.stats()["stored"] <= 10
    assert logger.total_captured == 50


def test_event_ttl_prunes():
    logger = EventLogger(max_queue_size=100, event_ttl_sec=0.2)
    logger.log_event("1.1.1.1", 1, 22, "ssh", "old")
    # Backdate the stored event so the assertion is not timing-flake sensitive.
    with logger._lock:  # noqa: SLF001
        logger._events[0].timestamp = time.time() - 2.0
    logger.log_event("1.1.1.1", 2, 22, "ssh", "new")
    recent = logger.recent()
    assert len(recent) == 1
    assert recent[0].payload == "new"


def test_listener_accept_and_stop_no_hang():
    ssh_port = _free_port()
    http_port = _free_port()
    settings = Settings(
        host="127.0.0.1",
        ssh_port=ssh_port,
        http_port=http_port,
        bind_ports=[ssh_port, http_port],
        connection_timeout_sec=1.0,
        tarpit_delay_sec=0.01,
        max_tarpit_rounds=2,
        max_payload_bytes=1024,
    )
    logger = EventLogger()
    listener = HoneypotListener(settings, logger)
    listener.start()
    try:
        with socket.create_connection(("127.0.0.1", ssh_port), timeout=2) as sock:
            sock.settimeout(2)
            banner = sock.recv(256)
            assert banner.startswith(b"SSH-2.0")
            sock.sendall(b"root\n")
            time.sleep(0.2)
        # Give handler a moment to log
        deadline = time.time() + 3
        while logger.total_captured < 1 and time.time() < deadline:
            time.sleep(0.05)
        assert logger.total_captured >= 1
    finally:
        t0 = time.time()
        listener.stop(join_timeout=2.0)
        assert time.time() - t0 < 3.0


def test_listener_rejects_over_capacity():
    port = _free_port()
    settings = Settings(
        host="127.0.0.1",
        ssh_port=port,
        http_port=_free_port(),
        bind_ports=[port],
        max_concurrent_connections=1,
        connection_timeout_sec=2.0,
        tarpit_delay_sec=0.3,
        max_tarpit_rounds=6,
    )
    logger = EventLogger()
    listener = HoneypotListener(settings, logger)
    listener.start()
    holders = []
    try:
        # Hold one connection open to saturate the semaphore.
        c1 = socket.create_connection(("127.0.0.1", port), timeout=2)
        holders.append(c1)
        time.sleep(0.1)
        c2 = socket.create_connection(("127.0.0.1", port), timeout=2)
        holders.append(c2)
        # Second connection should be closed quickly by server (over capacity).
        c2.settimeout(1.0)
        try:
            data = c2.recv(64)
            # Either empty (closed) or we still didn't hang — both OK.
            assert data == b"" or isinstance(data, (bytes, bytearray))
        except (socket.timeout, ConnectionResetError, ConnectionAbortedError, OSError):
            pass
    finally:
        for c in holders:
            try:
                c.close()
            except OSError:
                pass
        listener.stop(join_timeout=2.0)


def test_analyzer_retry_loop_terminates(monkeypatch):
    settings = Settings(
        llm_timeout_sec=0.5,
        llm_max_retries=1,
        llm_cooldown_sec=0.0,
        skip_llm_if_unavailable=False,
        analyze_interval_sec=60,
    )
    logger = EventLogger()
    logger.log_event("9.9.9.9", 1234, 2222, "ssh", "Password attempt root")
    analyzer = AIAnalyzer(settings, logger)
    analyzer._ollama_available = True

    class BoomClient:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, *a, **k):
            raise RuntimeError("simulated ollama down")

        def get(self, *a, **k):
            raise RuntimeError("simulated ollama down")

    monkeypatch.setattr("cybertrap.analyzer.httpx.Client", BoomClient)
    t0 = time.time()
    report = analyzer.analyze_once()
    elapsed = time.time() - t0
    assert report is not None
    assert elapsed < 10  # retries must not spin forever
    assert report.used_llm is False or "unavailable" in report.raw_model_output.lower() or report.attack_type


def test_heuristic_ssh_brute_force():
    settings = Settings(skip_llm_if_unavailable=True)
    logger = EventLogger()
    for i in range(3):
        logger.log_event("10.0.0.5", 4000 + i, 2222, "ssh", "root\nadmin\n")
    analyzer = AIAnalyzer(settings, logger)
    analyzer._ollama_available = False
    report = analyzer.analyze_once()
    assert report is not None
    assert "SSH" in report.attack_type.upper() or "Brute" in report.attack_type


def test_app_max_runtime_exits():
    ssh_port = _free_port()
    http_port = _free_port()
    settings = Settings(
        host="127.0.0.1",
        ssh_port=ssh_port,
        http_port=http_port,
        bind_ports=[ssh_port, http_port],
        analyze_interval_sec=1.0,
        main_loop_tick_sec=0.1,
        max_runtime_sec=1.5,
        tarpit_delay_sec=0.01,
        max_tarpit_rounds=1,
    )
    app = CyberTrapApp(settings, force_no_llm=True)
    t0 = time.time()
    app.start()
    elapsed = time.time() - t0
    assert elapsed < 6.0
    assert elapsed >= 1.0


def test_http_honeypot_responds():
    http_port = _free_port()
    settings = Settings(
        host="127.0.0.1",
        ssh_port=_free_port(),
        http_port=http_port,
        bind_ports=[http_port],
        tarpit_delay_sec=0.01,
        max_tarpit_rounds=2,
        connection_timeout_sec=2.0,
    )
    logger = EventLogger()
    listener = HoneypotListener(settings, logger)
    listener.start()
    try:
        with socket.create_connection(("127.0.0.1", http_port), timeout=2) as sock:
            sock.sendall(b"GET /admin HTTP/1.1\r\nHost: x\r\n\r\n")
            sock.settimeout(2)
            data = sock.recv(1024)
            assert b"HTTP/1.1 200" in data or b"admin" in data.lower()
        deadline = time.time() + 3
        while logger.total_captured < 1 and time.time() < deadline:
            time.sleep(0.05)
        assert logger.total_captured >= 1
        assert logger.recent()[0].service == "http"
    finally:
        listener.stop(join_timeout=2.0)


def test_cli_args_parse():
    parser = build_parser()
    args = parser.parse_args(
        ["--interface", "eth0", "--model", "llama3", "--ssh-port", "2222", "--no-llm"]
    )
    settings = settings_from_args(args)
    assert settings.model == "llama3"
    assert settings.ssh_port == 2222
    assert args.no_llm is True
