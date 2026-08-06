from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import re
import socket
from tempfile import TemporaryDirectory
from threading import Lock


Environment = dict[str, str]
Initializer = Callable[[Path], tuple[Path, Path, Environment]]
SESSION_ID = re.compile(r"[A-Za-z0-9-]{1,64}\Z")


@dataclass(frozen=True)
class RuntimeState:
    module_root: Path
    state_root: Path
    environment: Environment
    broker_socket: socket.socket


class RuntimeStateStore:
    def __init__(self, root: Path, initialize: Initializer) -> None:
        self._root = root
        self._initialize = initialize
        self._lock = Lock()
        self._states: dict[str, RuntimeState] = {}
        self._socket_aliases = TemporaryDirectory(prefix="rka-w-")

    def get(self, session_id: str) -> RuntimeState:
        if SESSION_ID.fullmatch(session_id) is None:
            raise ValueError("invalid WebUI test session")
        with self._lock:
            existing = self._states.get(session_id)
            if existing is not None:
                return existing
            session_root = self._root / f"session-{session_id}"
            session_root.mkdir(mode=0o700)
            module_root, state_root, environment = self._initialize(session_root)
            broker_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            broker_path = state_root / "run" / "sockets" / "broker.sock"
            socket_alias = Path(self._socket_aliases.name) / str(len(self._states))
            socket_alias.symlink_to(broker_path.parent, target_is_directory=True)
            broker_socket.bind(str(socket_alias / "broker.sock"))
            broker_path.chmod(0o600)
            state = RuntimeState(module_root, state_root, environment, broker_socket)
            self._states[session_id] = state
            return state

    def close(self) -> None:
        with self._lock:
            for state in self._states.values():
                state.broker_socket.close()
            self._states.clear()
            self._socket_aliases.cleanup()
