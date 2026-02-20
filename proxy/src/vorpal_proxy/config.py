import os
from dataclasses import dataclass
from pathlib import Path


DEFAULT_TARGET_URL = "ws://127.0.0.1:4500"
DEFAULT_LOG_FILE = "vorpal_proxy.log"


@dataclass(frozen=True)
class ProxyConfig:
    target_url: str
    log_file: Path

    @classmethod
    def from_env(cls) -> "ProxyConfig":
        target_url = os.environ.get("VORPAL_PROXY_TARGET", DEFAULT_TARGET_URL)
        log_file = Path(os.environ.get("VORPAL_PROXY_LOG_FILE", DEFAULT_LOG_FILE))

        return cls(
            target_url=target_url,
            log_file=log_file,
        )
