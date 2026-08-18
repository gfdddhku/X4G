import asyncio
import secrets
from datetime import datetime

from fastapi import WebSocket, WebSocketDisconnect

import main

LINKS = main.LINKS
LINKS_LOCK = main.LINKS_LOCK
stats = main.stats
hourly_traffic = main.hourly_traffic
connections = main.connections
error_logs = main.error_logs
logger = main.logger

is_link_allowed = main.is_link_allowed
is_ip_allowed = main.is_ip_allowed
save_state = main.save_state
log_activity = main.log_activity
now_ir = main.now_ir

from speed_limit import throttle

RELAY_BUF = 256 * 1024


def _ws_client_ip(ws: WebSocket) -> str:
    fwd = ws.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real = ws.headers.get("x-real-ip")
    if real:
        return real.strip()
    return ws.client.host if ws.client else "نامشخص"


async def parse_vless_header(chunk: bytes):
    if len(chunk) < 24:
        raise ValueError("chunk too small")

    pos = 1
    pos += 16

    addon_len = chunk[pos]
    pos += 1 + addon_len

    command = chunk[pos]
    pos += 1

    port = int.from_bytes(chunk[pos:pos + 2], "big")
    pos += 2

    addr_type = chunk[pos]
    pos += 1

    if addr_type == 1:
        address = ".".join(str(x) for x in chunk[pos:pos + 4])
        pos += 4

    elif addr_type == 2:
        length = chunk[pos]
        pos += 1
        address = chunk[pos:pos + length].decode(
            "utf-8",
            errors="ignore"
        )
        pos += length

    elif addr_type == 3:
        raw = chunk[pos:pos + 16]
        pos += 16
        address = ":".join(
            f"{raw[i]:02x}{raw[i+1]:02x}"
            for i in range(0, 16, 2)
        )

    else:
        raise ValueError("unknown addr")

    return command, address, port, chunk[pos:]


async def check_and_use(uid: str, size: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)

        if link is None:
            return False

        if not is_link_allowed(link):
            return False

        link["used_bytes"] += size
        stats["total_bytes"] += size

        hourly_traffic[
            now_ir().strftime("%H:00")
        ] += size

    return True
    async def relay_ws_to_tcp(
    ws: WebSocket,
    writer: asyncio.StreamWriter,
    conn_id: str,
    uid: str
):
    try:
        while True:
            msg = await ws.receive()

            if msg["type"] == "websocket.disconnect":
                break

            data = msg.get("bytes")

            if data is None:
                data = (msg.get("text") or "").encode()

            if not data:
                continue

            if not await check_and_use(uid, len(data)):
                await ws.close(
                    code=1008,
                    reason="quota disabled"
                )
                break

            await throttle(uid, len(data))

            stats["total_requests"] += 1

            if conn_id in connections:
                connections[conn_id]["bytes"] += len(data)

            writer.write(data)

            if writer.transport.get_write_buffer_size() > RELAY_BUF:
                await writer.drain()

    except Exception:
        pass

    finally:
        try:
            writer.write_eof()
        except Exception:
            pass


async def relay_tcp_to_ws(
    ws: WebSocket,
    reader: asyncio.StreamReader,
    conn_id: str,
    uid: str
):
    first = True

    try:
        while True:
            data = await reader.read(RELAY_BUF)

            if not data:
                break

            if not await check_and_use(uid, len(data)):
                await ws.close(
                    code=1008,
                    reason="quota disabled"
                )
                break

            await throttle(uid, len(data))

            if conn_id in connections:
                connections[conn_id]["bytes"] += len(data)

            if first:
                data = b"\x00\x00" + data
                first = False

            await ws.send_bytes(data)

    except Exception:
        pass


async def websocket_tunnel(
    ws: WebSocket,
    uuid: str
):
    await ws.accept()

    async with LINKS_LOCK:
        link = LINKS.get(uuid)

    if not is_link_allowed(link):
        await ws.close(
            code=1008,
            reason="not allowed"
        )
        return

    ip = _ws_client_ip(ws)

    if not is_ip_allowed(link, uuid, ip):
        await ws.close(
            code=1008,
            reason="ip limit"
        )
        return

    conn_id = secrets.token_urlsafe(6)

    connections[conn_id] = {
        "uuid": uuid,
        "ip": ip,
        "transport": "vless-ws",
        "connected_at": datetime.now().isoformat(),
        "bytes": 0,
    }

    writer = None

    try:
        first_msg = await asyncio.wait_for(
            ws.receive(),
            timeout=15
        )

        if first_msg["type"] == "websocket.disconnect":
            return

        first_chunk = (
            first_msg.get("bytes")
            or (first_msg.get("text") or "").encode()
        )

        if not first_chunk:
            return

        command, address, port, payload = await parse_vless_header(
            first_chunk
        )

        if not await check_and_use(
            uuid,
            len(first_chunk)
        ):
            await ws.close(
                code=1008,
                reason="quota"
            )
            return

        connections[conn_id]["bytes"] += len(first_chunk)

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                address,
                port
            ),
            timeout=10
        )

        if payload:
            writer.write(payload)
            await writer.drain()

        tasks = {
            asyncio.create_task(
                relay_ws_to_tcp(
                    ws,
                    writer,
                    conn_id,
                    uuid
                )
            ),
            asyncio.create_task(
                relay_tcp_to_ws(
                    ws,
                    reader,
                    conn_id,
                    uuid
                )
            ),
        }

        done, pending = await asyncio.wait(
            tasks,
            return_when=asyncio.FIRST_COMPLETED
        )

        for task in pending:
            task.cancel()

    except Exception as exc:
        error_logs.append({
            "error": str(exc),
            "time": datetime.now().isoformat()
        })

    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        connections.pop(conn_id, None)
        # پایان relay_vless.py

__all__ = [
    "RELAY_BUF",
    "parse_vless_header",
    "check_and_use",
    "relay_ws_to_tcp",
    "relay_tcp_to_ws",
    "websocket_tunnel",
]
