import asyncio
from datetime import datetime, timezone
from importlib.resources import files
import json
import logging
import sys

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
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
    login_lock = asyncio.Lock()
    login_task = None
    login_output = []
    login_phase = "idle"
    login_exit_code = None
    login_started_at = None
    login_finished_at = None
    login_version = 0
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def append_login_output(line):
        nonlocal login_version
        login_output.append(line)
        if len(login_output) > 400:
            del login_output[:-400]
        login_version += 1

    def get_login_status():
        status = login_phase
        if login_task is not None and not login_task.done():
            if login_phase not in {"running", "restarting"}:
                status = "running"

        return {
            "status": status,
            "complete": status in {"succeeded", "failed"},
            "exitCode": login_exit_code,
            "startedAt": login_started_at,
            "finishedAt": login_finished_at,
            "version": login_version,
            "output": "\n".join(login_output),
        }

    async def read_text_if_exists(path):
        try:
            text = await asyncio.to_thread(path.read_text, encoding="utf-8")
        except FileNotFoundError:
            return None
        except Exception as exc:
            logger.warning("failed to read file %s: %s", path, exc)
            return None
        return text.strip()

    async def write_text(path, content):
        await asyncio.to_thread(path.parent.mkdir, parents=True, exist_ok=True)
        await asyncio.to_thread(path.write_text, content, encoding="utf-8")

    async def app_server_ready_probe():
        initialize_payload = {
            "id": "azlogin-restart-probe",
            "method": "initialize",
            "params": {"clientInfo": {"name": "vorpal-proxy", "version": "0.1.0"}},
        }
        try:
            async with asyncio.timeout(4):
                async with websockets.connect(
                    config.target_url,
                    compression=None,
                    max_size=None,
                    ping_interval=None,
                ) as server_ws:
                    await server_ws.send(json.dumps(initialize_payload))
                    raw_response = await server_ws.recv()
        except Exception as exc:
            logger.info("app-server readiness probe failed: %s", exc)
            return False

        try:
            response = json.loads(raw_response)
        except Exception as exc:
            logger.info("app-server readiness probe response parse failed: %s", exc)
            return False

        return isinstance(response, dict) and response.get("id") == "azlogin-restart-probe"

    async def restart_app_server_and_wait():
        request_token = datetime.now(timezone.utc).isoformat()
        previous_done_token = await read_text_if_exists(config.app_server_restart_done_file)
        await write_text(config.app_server_restart_request_file, f"{request_token}\n")
        append_login_output("Requested vorpal app-server restart.")
        append_login_output("Waiting for restart acknowledgement and backend readiness...")
        logger.info(
            "wrote app-server restart request token=%s file=%s",
            request_token,
            config.app_server_restart_request_file,
        )

        deadline = (
            asyncio.get_running_loop().time() + config.app_server_restart_timeout_seconds
        )
        while True:
            done_token = await read_text_if_exists(config.app_server_restart_done_file)
            token_acknowledged = done_token == request_token
            if token_acknowledged and await app_server_ready_probe():
                append_login_output("vorpal app-server restarted and is ready.")
                logger.info("app-server restart acknowledged token=%s", request_token)
                return

            now = asyncio.get_running_loop().time()
            if now >= deadline:
                detail = (
                    f"last_done_token={done_token!r}, previous_done_token={previous_done_token!r}"
                )
                raise TimeoutError(
                    "timed out waiting for app-server restart "
                    f"(token={request_token}, {detail})"
                )

            await asyncio.sleep(config.app_server_restart_poll_interval_seconds)

    async def run_az_login_device_code():
        nonlocal login_phase
        nonlocal login_exit_code
        nonlocal login_started_at
        nonlocal login_finished_at

        command = ["stdbuf", "-oL", "-eL", "az", "login", "--use-device-code"]
        login_phase = "running"
        login_started_at = datetime.now(timezone.utc).isoformat()
        login_finished_at = None
        login_exit_code = None
        logger.info("running startup auth command: %s", " ".join(command))
        append_login_output("$ az login --use-device-code")
        append_login_output("")
        append_login_output(
            "Waiting for completion. Use a separate browser window for https://microsoft.com/devicelogin when code is shown."
        )
        append_login_output("")

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        assert process.stdout is not None
        while True:
            raw_line = await process.stdout.readline()
            if not raw_line:
                break
            line = raw_line.decode("utf-8", errors="replace").rstrip()
            append_login_output(line)
            logger.info("startup auth output: %s", line)

        az_login_exit_code = await process.wait()
        if az_login_exit_code == 0:
            logger.info("startup auth command succeeded")
            append_login_output("")
            append_login_output("az login completed successfully.")
            append_login_output("")
            login_phase = "restarting"
            try:
                await restart_app_server_and_wait()
            except Exception as exc:
                login_exit_code = 1
                login_phase = "failed"
                logger.warning("app-server restart after az login failed: %s", exc)
                append_login_output("")
                append_login_output(f"App-server restart failed: {exc}")
            else:
                login_exit_code = 0
                login_phase = "succeeded"
        else:
            login_exit_code = az_login_exit_code
            login_phase = "failed"
            logger.warning(
                "startup auth command failed with exit code %s",
                az_login_exit_code,
            )
            append_login_output("")
            append_login_output(f"az login exited with code {az_login_exit_code}.")

        login_finished_at = datetime.now(timezone.utc).isoformat()

    async def ensure_login_running():
        nonlocal login_phase
        nonlocal login_task
        nonlocal login_exit_code
        nonlocal login_started_at
        nonlocal login_finished_at

        async with login_lock:
            is_running = login_task is not None and not login_task.done()
            if is_running:
                return False
            login_output.clear()
            login_phase = "running"
            login_exit_code = None
            login_started_at = None
            login_finished_at = None
            login_task = asyncio.create_task(run_az_login_device_code())
            return True

    @app.on_event("startup")
    async def startup_log():
        logger.info(
            "proxy app configured: ui=bundled ws->%s restart_request=%s restart_done=%s",
            config.target_url,
            config.app_server_restart_request_file,
            config.app_server_restart_done_file,
        )

    @app.get("/", include_in_schema=False)
    async def index():
        return HTMLResponse(
            (
                "<!doctype html><title>Vorpal Startup</title>"
                "<h1>Vorpal Proxy Startup</h1>"
                "<p><a href=\"/azlogin\">Run az login --use-device-code</a></p>"
                "<p><a href=\"/cli\">Open Vorpal CLI proxy UI</a></p>"
            ),
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/azlogin", include_in_schema=False)
    async def azlogin_page():
        await ensure_login_running()
        return HTMLResponse(
            (
                "<!doctype html><title>Vorpal Azure Login</title>"
                "<meta charset='utf-8'>"
                "<style>"
                "body{font-family:ui-monospace,Menlo,Consolas,monospace;padding:16px;line-height:1.4;user-select:text;-webkit-user-select:text;}"
                "#status{font-weight:700;margin-bottom:8px;}"
                "pre{white-space:pre-wrap;background:#111;color:#eee;padding:12px;border-radius:6px;min-height:220px;user-select:text;-webkit-user-select:text;cursor:text;}"
                "a{color:#0a66c2;}"
                "</style>"
                "<h1>Azure Device Login</h1>"
                "<div id='status'>starting...</div>"
                "<p>Use a separate browser window for <a href='https://microsoft.com/devicelogin' target='_blank' rel='noreferrer'>https://microsoft.com/devicelogin</a>.</p>"
                "<pre id='output'>(waiting for az output)</pre>"
                "<script>"
                "const statusEl=document.getElementById('status');"
                "const outEl=document.getElementById('output');"
                "let done=false;"
                "let redirected=false;"
                "async function tick(){"
                " try{"
                "  const r=await fetch('/azlogin/status',{cache:'no-store'});"
                "  const s=await r.json();"
                "  statusEl.textContent='status: '+s.status+(s.exitCode!==null?' (exitCode='+s.exitCode+')':'');"
                "  const sel=window.getSelection();"
                "  const hasSelection=sel&&sel.toString().length>0;"
                "  if(!hasSelection){"
                "   outEl.textContent=s.output||'(waiting for az output)';"
                "  }"
                "  if(s.complete&&s.status==='succeeded'&&!redirected){"
                "   redirected=true;"
                "   statusEl.textContent='status: succeeded (redirecting to /cli...)';"
                "   setTimeout(()=>window.location.assign('/cli'),700);"
                "   done=true;"
                "  }else if(s.complete){done=true;}"
                " }catch(e){statusEl.textContent='status: polling failed';}"
                " if(!done){setTimeout(tick,1000);}"
                "}"
                "tick();"
                "</script>"
            ),
            headers={"Cache-Control": "no-store"},
        )

    @app.post("/azlogin", include_in_schema=False)
    async def azlogin_start():
        started_now = await ensure_login_running()
        status = get_login_status()
        message = "started" if started_now else "already running"
        return JSONResponse(
            {
                "message": message,
                "status": status["status"],
                "startedAt": status["startedAt"],
            },
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/azlogin/status", include_in_schema=False)
    async def azlogin_status():
        return JSONResponse(
            get_login_status(),
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/azlogin/raw", include_in_schema=False)
    async def azlogin_raw():
        await ensure_login_running()
        return PlainTextResponse(
            get_login_status().get("output", ""),
            status_code=200,
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/cli", include_in_schema=False)
    @app.get("/cli/", include_in_schema=False)
    async def cli_index():
        return HTMLResponse(ui_html, headers={"Cache-Control": "no-store"})

    @app.get("/cli/vorpal.html", include_in_schema=False)
    async def cli_vorpal_html():
        return HTMLResponse(ui_html, headers={"Cache-Control": "no-store"})

    @app.get("/{path:path}", include_in_schema=False)
    async def not_found(path):
        _ = path
        return PlainTextResponse(
            "Not Found",
            status_code=404,
            headers={"Cache-Control": "no-store"},
        )

    @app.websocket("/cli")
    async def websocket_cli(client_ws: WebSocket):
        await client_ws.accept()
        await handler(client_ws, target_url=config.target_url, logger=logger)

    return app


def create_app() -> FastAPI:
    return build_app(ProxyConfig.from_env())
