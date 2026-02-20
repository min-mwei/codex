import asyncio
from importlib.resources import files
import json
import logging
import sys

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse
import websockets
from websockets.exceptions import ConnectionClosed, InvalidHandshake, InvalidURI

from .config import ProxyConfig


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


def setup_logger(log_file):
    logger = logging.getLogger("vorpal-proxy")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    formatter = logging.Formatter("[%(asctime)s] %(message)s")
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    return logger


def load_ui(logger):
    try:
        return files("vorpal_proxy").joinpath("vorpal.html").read_text(encoding="utf-8")
    except Exception as exc:
        logger.error("failed to read bundled UI asset: %s", exc)
        return (
            "<!doctype html><title>Vorpal Proxy</title>"
            "<h1>Bundled UI not found</h1>"
            "<p>Expected package asset: vorpal_proxy/vorpal.html</p>"
        )


async def safe_close_client(client_ws, code=1000, reason=""):
    if client_ws.client_state.name != "CONNECTED":
        return
    try:
        await client_ws.close(code=code, reason=reason)
    except Exception:
        pass


async def send_upstream_error(client_ws, target_url, exc, logger):
    logger.warning("failed to connect to backend %s: %s", target_url, exc)
    payload = {
        "error": {
            "message": f"Unable to connect to backend at {target_url}. Verify the app-server is running."
        }
    }
    try:
        await client_ws.send_text(json.dumps(payload))
    except Exception as send_exc:
        logger.info("failed to send backend error to client: %s", send_exc)
    await safe_close_client(client_ws, code=1013, reason="backend unavailable")


async def bridge(client_ws, target_url, logger):
    try:
        server_ws = await websockets.connect(
            target_url,
            compression=None,
            max_size=None,
            ping_interval=None,
        )
    except (
        OSError,
        asyncio.TimeoutError,
        InvalidHandshake,
        ConnectionClosed,
        InvalidURI,
    ) as exc:
        await send_upstream_error(client_ws, target_url, exc, logger)
        return
    except Exception as exc:
        logger.error("unexpected backend connect error: %s", exc)
        await send_upstream_error(client_ws, target_url, exc, logger)
        return

    async with server_ws:
        logger.info("connected to backend %s", target_url)

        async def pipe_client_to_server():
            try:
                while True:
                    event = await client_ws.receive()
                    event_type = event.get("type")
                    if event_type == "websocket.disconnect":
                        break
                    if event_type != "websocket.receive":
                        continue
                    text = event.get("text")
                    data = event.get("bytes")
                    message = text if text is not None else data
                    if message is None:
                        continue
                    logger.info(
                        "client->server %s bytes: %s",
                        len(message),
                        _preview(message),
                    )
                    await server_ws.send(message)
            except WebSocketDisconnect as exc:
                logger.info("client->server closed: %s", exc)
            except Exception as exc:
                logger.info("client->server error: %s", exc)
            finally:
                try:
                    await server_ws.close()
                except Exception:
                    pass

        async def pipe_server_to_client():
            try:
                async for message in server_ws:
                    logger.info(
                        "server->client %s bytes: %s",
                        len(message),
                        _preview(message),
                    )
                    if isinstance(message, bytes):
                        await client_ws.send_bytes(message)
                    else:
                        await client_ws.send_text(message)
            except ConnectionClosed as exc:
                logger.info("server->client closed: %s", exc)
            except Exception as exc:
                logger.info("server->client error: %s", exc)
            finally:
                await safe_close_client(client_ws)

        to_server = asyncio.create_task(pipe_client_to_server())
        to_client = asyncio.create_task(pipe_server_to_client())
        _, pending = await asyncio.wait(
            {to_server, to_client},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)


async def handler(client_ws, *, target_url, logger):
    peer = client_ws.client
    logger.info("client connected %s", peer)
    try:
        await bridge(client_ws, target_url, logger)
    finally:
        logger.info("client disconnected %s", peer)


def build_app(config: ProxyConfig) -> FastAPI:
    logger = setup_logger(config.log_file)
    ui_html = load_ui(logger)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.on_event("startup")
    async def startup_log():
        logger.info(
            "proxy app configured: ui=bundled ws->%s",
            config.target_url,
        )

    @app.get("/", include_in_schema=False)
    async def index():
        return HTMLResponse(ui_html, headers={"Cache-Control": "no-store"})

    @app.get("/vorpal.html", include_in_schema=False)
    async def vorpal_html():
        return HTMLResponse(ui_html, headers={"Cache-Control": "no-store"})

    @app.get("/{path:path}", include_in_schema=False)
    async def not_found(path):
        _ = path
        return PlainTextResponse(
            "Not Found",
            status_code=404,
            headers={"Cache-Control": "no-store"},
        )

    @app.websocket("/")
    async def websocket_root(client_ws: WebSocket):
        await client_ws.accept()
        await handler(client_ws, target_url=config.target_url, logger=logger)

    return app


def create_app() -> FastAPI:
    return build_app(ProxyConfig.from_env())
