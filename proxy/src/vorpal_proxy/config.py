import os
from dataclasses import dataclass
from pathlib import Path


DEFAULT_TARGET_URL = "ws://127.0.0.1:4500"
DEFAULT_LOG_FILE = "vorpal_proxy.log"
DEFAULT_APP_SERVER_RESTART_REQUEST_FILE = "/tmp/vorpal_app_server.restart"
DEFAULT_APP_SERVER_RESTART_DONE_FILE = "/tmp/vorpal_app_server.restarted"
DEFAULT_APP_SERVER_RESTART_TIMEOUT_SECONDS = 45.0
DEFAULT_APP_SERVER_RESTART_POLL_INTERVAL_SECONDS = 0.5


def _float_env(name: str, default: float) -> float:
    value = os.environ.get(name)
    if value is None:
        return default

    try:
        return float(value)
    except ValueError:
        return default


@dataclass(frozen=True)
class ProxyConfig:
    target_url: str
    log_file: Path
    app_server_restart_request_file: Path
    app_server_restart_done_file: Path
    app_server_restart_timeout_seconds: float
    app_server_restart_poll_interval_seconds: float

    @classmethod
    def from_env(cls) -> "ProxyConfig":
        target_url = os.environ.get("VORPAL_PROXY_TARGET", DEFAULT_TARGET_URL)
        log_file = Path(os.environ.get("VORPAL_PROXY_LOG_FILE", DEFAULT_LOG_FILE))
        app_server_restart_request_file = Path(
            os.environ.get(
                "VORPAL_APP_SERVER_RESTART_REQUEST_FILE",
                DEFAULT_APP_SERVER_RESTART_REQUEST_FILE,
            )
        )
        app_server_restart_done_file = Path(
            os.environ.get(
                "VORPAL_APP_SERVER_RESTART_DONE_FILE",
                DEFAULT_APP_SERVER_RESTART_DONE_FILE,
            )
        )
        app_server_restart_timeout_seconds = _float_env(
            "VORPAL_APP_SERVER_RESTART_TIMEOUT_SECONDS",
            DEFAULT_APP_SERVER_RESTART_TIMEOUT_SECONDS,
        )
        app_server_restart_poll_interval_seconds = _float_env(
            "VORPAL_APP_SERVER_RESTART_POLL_INTERVAL_SECONDS",
            DEFAULT_APP_SERVER_RESTART_POLL_INTERVAL_SECONDS,
        )

        return cls(
            target_url=target_url,
            log_file=log_file,
            app_server_restart_request_file=app_server_restart_request_file,
            app_server_restart_done_file=app_server_restart_done_file,
            app_server_restart_timeout_seconds=app_server_restart_timeout_seconds,
            app_server_restart_poll_interval_seconds=app_server_restart_poll_interval_seconds,
        )
