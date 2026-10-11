"""Central configuration with safe defaults for loop / resource limits."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class Settings:
    """Runtime settings. All loop-related limits live here so they stay consistent."""

    host: str = "0.0.0.0"
    interface: str = "eth0"
    model: str = "llama3"
    ollama_base_url: str = "http://127.0.0.1:11434"

    # Non-privileged defaults so Windows / non-root can test without sudo.
    ssh_port: int = 2222
    http_port: int = 8080

    # Connection / tarpit safety
    max_concurrent_connections: int = 64
    connection_timeout_sec: float = 10.0
    read_chunk_size: int = 4096
    max_payload_bytes: int = 16_384
    tarpit_delay_sec: float = 0.5
    max_tarpit_rounds: int = 8

    # Logger / analyzer cadence
    analyze_interval_sec: float = 15.0
    max_events_per_batch: int = 20
    max_queue_size: int = 500
    event_ttl_sec: float = 3600.0

    # AI call safety
    llm_timeout_sec: float = 60.0
    llm_max_retries: int = 1
    llm_cooldown_sec: float = 5.0
    skip_llm_if_unavailable: bool = True

    # Main loop safety
    main_loop_tick_sec: float = 0.5
    max_runtime_sec: float | None = None  # None = run until Ctrl+C

    bind_ports: List[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.bind_ports:
            self.bind_ports = [self.ssh_port, self.http_port]


DEFAULT_SETTINGS = Settings()
