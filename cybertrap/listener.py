"""Fake SSH / HTTP honeypot listeners with hard loop and concurrency guards."""

from __future__ import annotations

import socket
import threading
import time
from typing import Callable, Dict, Optional

from cybertrap.config import Settings
from cybertrap.logger import EventLogger


OnEventCallback = Callable[[object], None]


class HoneypotListener:
    """
    Accepts TCP connections on configured ports and tar pits clients briefly.

    Safety guarantees:
    - Bounded concurrent handlers (Semaphore)
    - Per-connection timeout
    - Max read bytes / max tarpit rounds (no infinite read loops)
    - Clean shutdown via Event flag + socket close
    """

    SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
    HTTP_RESPONSE = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Apache/2.4.41 (Ubuntu)\r\n"
        b"Content-Type: text/html\r\n"
        b"Connection: close\r\n"
        b"Content-Length: 78\r\n"
        b"\r\n"
        b"<html><body><h1>Welcome to admin panel</h1><p>Login required.</p></body></html>"
    )

    def __init__(
        self,
        settings: Settings,
        event_logger: EventLogger,
        on_event: Optional[OnEventCallback] = None,
    ) -> None:
        self.settings = settings
        self.logger = event_logger
        self.on_event = on_event
        self._stop = threading.Event()
        self._sockets: Dict[int, socket.socket] = {}
        self._threads: list[threading.Thread] = []
        self._active = threading.Semaphore(settings.max_concurrent_connections)
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        return not self._stop.is_set() and bool(self._threads)

    def start(self) -> None:
        if self._threads:
            return
        self._stop.clear()
        for port in self.settings.bind_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1.0)  # accept loop must wake periodically
            sock.bind((self.settings.host, port))
            sock.listen(32)
            self._sockets[port] = sock
            t = threading.Thread(
                target=self._accept_loop,
                args=(sock, port),
                name=f"honeypot-accept-{port}",
                daemon=True,
            )
            t.start()
            self._threads.append(t)

    def stop(self, join_timeout: float = 3.0) -> None:
        self._stop.set()
        with self._lock:
            sockets = list(self._sockets.values())
            self._sockets.clear()
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass
        deadline = time.time() + join_timeout
        for t in self._threads:
            remaining = max(0.0, deadline - time.time())
            t.join(timeout=remaining)
        self._threads.clear()

    def _service_for_port(self, port: int) -> str:
        if port == self.settings.ssh_port:
            return "ssh"
        if port == self.settings.http_port:
            return "http"
        return "tcp"

    def _accept_loop(self, sock: socket.socket, port: int) -> None:
        """Accept loop: bounded by stop flag + socket timeout (never busy-spins)."""
        idle_spins = 0
        max_idle_spins_before_yield = 100  # extra safety against tight timeout loops

        while not self._stop.is_set():
            try:
                client, addr = sock.accept()
                idle_spins = 0
            except socket.timeout:
                idle_spins += 1
                if idle_spins >= max_idle_spins_before_yield:
                    time.sleep(0.01)
                    idle_spins = 0
                continue
            except OSError:
                if self._stop.is_set():
                    break
                time.sleep(0.05)
                continue

            acquired = self._active.acquire(blocking=False)
            if not acquired:
                # Over capacity: refuse quickly instead of queueing forever.
                try:
                    client.close()
                except OSError:
                    pass
                continue

            handler = threading.Thread(
                target=self._handle_client_safe,
                args=(client, addr, port),
                name=f"honeypot-handler-{port}-{addr[0]}",
                daemon=True,
            )
            handler.start()

    def _handle_client_safe(self, client: socket.socket, addr: tuple, port: int) -> None:
        try:
            self._handle_client(client, addr, port)
        finally:
            self._active.release()
            try:
                client.close()
            except OSError:
                pass

    def _handle_client(self, client: socket.socket, addr: tuple, port: int) -> None:
        src_ip, src_port = addr[0], addr[1]
        service = self._service_for_port(port)
        client.settimeout(self.settings.connection_timeout_sec)
        received = bytearray()

        try:
            if service == "ssh":
                client.sendall(self.SSH_BANNER)

            rounds = 0
            while (
                rounds < self.settings.max_tarpit_rounds
                and len(received) < self.settings.max_payload_bytes
                and not self._stop.is_set()
            ):
                rounds += 1
                try:
                    chunk = client.recv(self.settings.read_chunk_size)
                except socket.timeout:
                    break
                if not chunk:
                    break
                remaining = self.settings.max_payload_bytes - len(received)
                received.extend(chunk[:remaining])
                if len(received) >= self.settings.max_payload_bytes:
                    break

                # HTTP: respond as soon as headers look complete (avoid client/server
                # mutual wait deadlock on a second recv).
                if service == "http" and b"\r\n\r\n" in received:
                    break

                # Tarpit: slow response so scanners waste time (bounded rounds).
                time.sleep(self.settings.tarpit_delay_sec)
                if service == "ssh":
                    # Fake auth prompt bait; no real auth.
                    try:
                        client.sendall(b"Password: ")
                    except OSError:
                        break

            if service == "http":
                try:
                    client.sendall(self.HTTP_RESPONSE)
                except OSError:
                    pass

        except OSError:
            pass

        event = self.logger.log_event(
            src_ip=src_ip,
            src_port=src_port,
            dst_port=port,
            service=service,
            payload=bytes(received),
            notes=f"tarpit rounds completed against {service}",
        )
        if self.on_event:
            try:
                self.on_event(event)
            except Exception:
                # Never let dashboard/callback crashes kill the listener.
                pass
