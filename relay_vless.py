# relay_vless.py
# VLESS Relay - بدون import مستقیم از main برای جلوگیری از circular import

import asyncio
import secrets
from datetime import datetime

from fastapi import WebSocket, WebSocketDisconnect
from speed_limit import throttle


RELAY_BUF = 256 * 1024


def get_main():
    import main
    return main


def _ws_client_ip(ws: WebSocket) -> str:
    fwd = ws.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()

    real = ws.headers.get("x-real-ip")
    if real:
        return real.strip()

    return ws.client.host if ws.client else "unknown"


async def parse_vless_header(chunk: bytes):
    if len(chunk) < 24:
        raise ValueError("invalid header")

    pos = 1
    pos += 16

    addon = chunk[pos]
    pos += 1 + addon

    command = chunk[pos]
    pos += 1

    port = int.from_bytes(
        chunk[pos:pos + 2],
        "big"
    )
    pos += 2

    addr_type = chunk[pos]
    pos += 1

    if addr_type == 1:
        address = ".".join(
            str(x) for x in chunk[pos:pos + 4]
        )
        pos += 4

    elif addr_type == 2:
        ln = chunk[pos]
        pos += 1
        address = chunk[pos:pos + ln].decode(
            "utf-8",
            errors="ignore"
        )
        pos += ln

    elif addr_type == 3:
        raw = chunk[pos:pos + 16]
        pos += 16
        address = ":".join(
            f"{raw[i]:02x}{raw[i+1]:02x}"
            for i in range(0,16,2)
        )

    else:
        raise ValueError("unknown address")

    return command, address, port, chunk[pos:]


async def check_and_use(uid: str, n: int):
    main = get_main()

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
    ws,
    writer,
    conn_id,
    uid
):
    main = get_main()

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

            if not await check_and_use(
                uid,
                len(data)
            ):
                break

            await throttle(
                uid,
                len(data)
            )

            main.stats["total_requests"] += 1
            main.connections[conn_id]["bytes"] += len(data)

            writer.write(data)

            if writer.transport.get_write_buffer_size() > RELAY_BUF:
                await writer.drain()

    except Exception:
        pass


async def relay_tcp_to_ws(
    ws,
    reader,
    conn_id,
    uid
):
    main = get_main()
    first = True

    try:
        while True:
            data = await reader.read(RELAY_BUF)

            if not data:
                break

            if not await check_and_use(
                uid,
                len(data)
            ):
                break

            await throttle(
                uid,
                len(data)
            )

            main.connections[conn_id]["bytes"] += len(data)

            if first:
                data = b"\x00\x00" + data
                first = False

            await ws.send_bytes(data)

    except Exception:
        pass
        async def websocket_tunnel(ws: WebSocket, uuid: str):
    main = get_main()

    await ws.accept()

    async with main.LINKS_LOCK:
        link = main.LINKS.get(uuid)

    if not main.is_link_allowed(link):
        await ws.close(
            code=1008,
            reason="not allowed"
        )
        return

    ip = _ws_client_ip(ws)

    if not main.is_ip_allowed(
        link,
        uuid,
        ip
    ):
        await ws.close(
            code=1008,
            reason="ip limit"
        )
        return

    conn_id = secrets.token_urlsafe(6)

    main.connections[conn_id] = {
        "uuid": uuid,
        "ip": ip,
        "transport": "vless-ws",
        "connected_at": datetime.now().isoformat(),
        "bytes": 0,
    }

    writer = None

    try:
        first = await asyncio.wait_for(
            ws.receive(),
            timeout=15
        )

        if first["type"] == "websocket.disconnect":
            return

        chunk = (
            first.get("bytes")
            or (first.get("text") or "").encode()
        )

        if not chunk:
            return

        command, address, port, payload = (
            await parse_vless_header(chunk)
        )

        if not await check_and_use(
            uuid,
            len(chunk)
        ):
            await ws.close(
                code=1008,
                reason="quota"
            )
            return

        main.stats["total_requests"] += 1
        main.connections[conn_id]["bytes"] += len(chunk)

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                address,
                port
            ),
            timeout=10
        )

        sock = writer.transport.get_extra_info(
            "socket"
        )

        if sock:
            import socket
            sock.setsockopt(
                socket.IPPROTO_TCP,
                socket.TCP_NODELAY,
                1
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

    except WebSocketDisconnect:
        pass

    except Exception as e:
        main.stats["total_errors"] += 1
        main.error_logs.append(
            {
                "error": str(e),
                "time": datetime.now().isoformat()
            }
        )

    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        main.connections.pop(
            conn_id,
            None
                )
