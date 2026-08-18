# relay_vless.py

import asyncio
import secrets
from datetime import datetime

from fastapi import WebSocket, WebSocketDisconnect

import main
from speed_limit import throttle

RELAY_BUF = 256 * 1024


def _ws_client_ip(ws: WebSocket) -> str:
    fwd = ws.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = ws.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
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

    port = int.from_bytes(chunk[pos:pos+2], "big")
    pos += 2

    addr_type = chunk[pos]
    pos += 1

    if addr_type == 1:
        address = ".".join(str(x) for x in chunk[pos:pos+4])
        pos += 4

    elif addr_type == 2:
        length = chunk[pos]
        pos += 1
        address = chunk[pos:pos+length].decode(
            "utf-8",
            errors="ignore"
        )
        pos += length

    elif addr_type == 3:
        raw = chunk[pos:pos+16]
        pos += 16
        address = ":".join(
            f"{raw[i]:02x}{raw[i+1]:02x}"
            for i in range(0,16,2)
        )

    else:
        raise ValueError("unknown addr")

    return command, address, port, chunk[pos:]


async def check_and_use(uid: str, n: int) -> bool:
    async with main.LINKS_LOCK:
        link = main.LINKS.get(uid)

        if link is None:
            return False

        if not main.is_link_allowed(link):
            return False

        link["used_bytes"] += n
        main.stats["total_bytes"] += n
        main.hourly_traffic[
            main.now_ir().strftime("%H:00")
        ] += n

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

            data = (
                msg.get("bytes")
                or (msg.get("text") or "").encode()
            )

            if not data:
                continue

            if not await check_and_use(uid, len(data)):
                await ws.close(
                    code=1008,
                    reason="disabled"
                )
                break

            await throttle(uid, len(data))

            main.stats["total_requests"] += 1
            main.connections[conn_id]["bytes"] += len(data)

            writer.write(data)

            if (
                writer.transport.get_write_buffer_size()
                > RELAY_BUF
            ):
                await writer.drain()

    except Exception:
        pass

    finally:
        try:
            writer.write_eof()
        except Exception:
            pass
