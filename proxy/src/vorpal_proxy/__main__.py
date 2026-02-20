import argparse
import os
import sys

import uvicorn


def parse_listen(listen):
    if ":" not in listen:
        raise SystemExit("--listen must be in host:port format")
    host, port_str = listen.rsplit(":", 1)
    try:
        port = int(port_str)
    except ValueError as exc:
        raise SystemExit("--listen port must be an integer") from exc
    return host, port


def main():
    parser = argparse.ArgumentParser(
        prog="vorpal-proxy",
        description="WebSocket proxy for codex app-server (strip extensions on backend)"
    )
    parser.add_argument(
        "--listen",
        default="127.0.0.1:4501",
        help="Listen address as host:port (default: 127.0.0.1:4501)",
    )
    parser.add_argument(
        "--target",
        default="ws://127.0.0.1:4500",
        help="Target ws:// URL (default: ws://127.0.0.1:4500)",
    )
    parser.add_argument(
        "--log-file",
        default="vorpal_proxy.log",
        help="Log file path (default: vorpal_proxy.log)",
    )
    args = parser.parse_args()

    host, port = parse_listen(args.listen)
    os.environ["VORPAL_PROXY_TARGET"] = args.target
    os.environ["VORPAL_PROXY_LOG_FILE"] = args.log_file

    uvicorn.run(
        "vorpal_proxy.app:create_app",
        factory=True,
        host=host,
        port=port,
        log_level="warning",
        access_log=False,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
