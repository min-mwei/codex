#!/usr/bin/env python3
import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

try:
    import websockets
    from websockets.http11 import Response
    from websockets.datastructures import Headers
except ImportError as exc:
    raise SystemExit(
        "Missing dependency: websockets. Install with: pip install websockets"
    ) from exc


def _preview(message, limit=200):
    if isinstance(message, bytes):
        try:
            text = message.decode("utf-8", errors="replace")
        except Exception:
            return f"<{len(message)} bytes>"
    else:
        text = message
    text = text.replace("\n", "\\n")
    if len(text) > limit:
        return text[:limit] + "…"
    return text


async def bridge(client_ws, target_url, logger):
    async with websockets.connect(
        target_url,
        compression=None,
        max_size=None,
        ping_interval=None,
    ) as server_ws:
        logger.info("connected to backend %s", target_url)

        async def pipe(src, dst, tag):
            try:
                async for message in src:
                    logger.info("%s %s bytes: %s", tag, len(message), _preview(message))
                    await dst.send(message)
            except Exception as exc:
                logger.info("%s closed: %s", tag, exc)
            finally:
                try:
                    await dst.close()
                except Exception:
                    pass

        to_server = asyncio.create_task(pipe(client_ws, server_ws, "client->server"))
        to_client = asyncio.create_task(pipe(server_ws, client_ws, "server->client"))
        done, pending = await asyncio.wait(
            {to_server, to_client}, return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()


async def handler(client_ws, _path=None, *, target_url, logger):
    peer = getattr(client_ws, "remote_address", None)
    logger.info("client connected %s", peer)
    try:
        await bridge(client_ws, target_url, logger)
    finally:
        logger.info("client disconnected %s", peer)


async def main():
    parser = argparse.ArgumentParser(
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
    parser.add_argument(
        "--ui-path",
        default="vorpal.html",
        help="Path to vorpal.html (default: vorpal.html in current directory)",
    )
    args = parser.parse_args()

    if ":" not in args.listen:
        raise SystemExit("--listen must be in host:port format")
    host, port_str = args.listen.rsplit(":", 1)
    port = int(port_str)

    logger = logging.getLogger("vorpal-proxy")
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("[%(asctime)s] %(message)s")
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    file_handler = logging.FileHandler(args.log_file)
    file_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    ui_file = Path(args.ui_path)
    if not ui_file.is_absolute():
        ui_file = Path(os.getcwd()) / ui_file

    def load_ui():
        try:
            return ui_file.read_text(encoding="utf-8")
        except Exception as exc:
            logger.error("failed to read UI file %s: %s", ui_file, exc)
            return (
                "<!doctype html><title>Vorpal Proxy</title>"
                "<h1>UI not found</h1>"
                f"<p>Expected: {ui_file}</p>"
            )

    def is_websocket_request(headers):
        if headers is None:
            return False
        upgrade = headers.get("Upgrade", "").lower()
        connection = headers.get("Connection", "").lower()
        return "upgrade" in connection and upgrade == "websocket"

    def make_response(status_code, body, content_type):
        reason = "OK" if status_code == 200 else "Not Found"
        hdrs = Headers()
        hdrs["Content-Type"] = content_type
        hdrs["Content-Length"] = str(len(body))
        hdrs["Cache-Control"] = "no-store"
        return Response(status_code, reason, hdrs, body)

    async def process_request(*args):
        path = None
        headers = None
        if len(args) == 2 and hasattr(args[1], "path"):
            # websockets >= 12: (connection, request)
            request = args[1]
            path = request.path
            headers = request.headers
        elif len(args) == 2:
            # websockets < 12: (path, request_headers)
            path, headers = args

        if is_websocket_request(headers):
            return None

        if path in ("/", "/vorpal.html"):
            body = load_ui().encode("utf-8")
            return make_response(200, body, "text/html; charset=utf-8")

        body = b"Not Found"
        return make_response(404, body, "text/plain; charset=utf-8")

    async def bound_handler(ws, path=None):
        await handler(ws, path, target_url=args.target, logger=logger)

    async with websockets.serve(
        bound_handler,
        host,
        port,
        max_size=None,
        ping_interval=None,
        process_request=process_request,
    ):
        logger.info(
            "proxy listening on http://%s:%s (ui) and ws://%s:%s -> %s",
            host,
            port,
            host,
            port,
            args.target,
        )
        await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
