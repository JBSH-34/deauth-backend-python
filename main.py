from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from scapy.layers.dot11 import Dot11
from prisma import Prisma
from scapy.all import sniff
from typing import List, AsyncGenerator, Any
from datetime import datetime
import asyncio
from pydantic import BaseModel
from icecream import ic  # IceCream 임포트


class DeauthRateResponse(BaseModel):
    timestamp: str
    deauth_rate: float
    deauth_packets: int
    total_packets: int


class DeauthHistoryResponse(BaseModel):
    timestamp: str
    count: int


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Manages the lifespan of the FastAPI application.
    Connects to the database on startup and disconnects on shutdown.
    """
    ic("Entering lifespan context manager")
    await startup_event()
    yield
    await shutdown_event()
    ic("Exiting lifespan context manager")


app = FastAPI(lifespan=lifespan)
db: Prisma = Prisma()

# List of connected WebSocket clients
clients: List[WebSocket] = []


async def startup_event() -> None:
    """
    Event handler for application startup.
    Connects to the database and starts the background task for packet sniffing.
    """
    ic("Starting up: Connecting to the database")
    await db.connect()
    ic("Database connected")
    ic("Starting background task: sniff_packets in a separate thread")

    # 현재 이벤트 루프를 가져와서 sniff_packets에 전달
    loop = asyncio.get_running_loop()
    asyncio.create_task(asyncio.to_thread(sniff_packets, loop))
    ic("Background task started in a separate thread")


async def shutdown_event() -> None:
    """
    Event handler for application shutdown.
    Disconnects from the database.
    """
    ic("Shutting down: Disconnecting from the database")
    await db.disconnect()
    ic("Database disconnected")


@app.websocket("/stream/deauth-rate")
async def stream_deauth_rate(websocket: WebSocket) -> None:
    """
    WebSocket endpoint to stream deauth packet rate to clients.
    Connects and continuously sends deauth rate updates every 5 seconds.

    Parameters:
        websocket (WebSocket): The WebSocket connection to the client.
    """
    ic("WebSocket connection accepted")
    await websocket.accept()
    clients.append(websocket)
    ic(f"WebSocket clients list: {clients}")
    try:
        while True:
            deauth_rate: DeauthRateResponse = await get_deauth_rate()
            ic("Sending deauth rate to client", deauth_rate)
            await websocket.send_json(deauth_rate.model_dump())
            await asyncio.sleep(5)  # Send every 5 seconds
    except WebSocketDisconnect:
        clients.remove(websocket)
        ic("WebSocket disconnected and removed from clients list")


@app.get("/detection/deauth-rate", response_model=DeauthRateResponse)
async def get_deauth_rate() -> DeauthRateResponse:
    """
    Endpoint to retrieve the current rate of deauth packets.

    Returns:
        DeauthRateResponse: A JSON object containing the timestamp, deauth rate, number of deauth packets,
              and the total packet count.
    """
    ic("Fetching deauth rate from the database")
    total_packets: int = await db.packet.count()
    ic(f"Total packets: {total_packets}")
    if total_packets == 0:
        ic("No packets found")
        return DeauthRateResponse(
            timestamp=datetime.now().isoformat(),
            deauth_rate=0.0,
            deauth_packets=0,
            total_packets=0
        )

    deauth_packets: int = await db.packet.count(where={"is_deauth": True})
    ic(f"Deauth packets: {deauth_packets}")
    deauth_rate: float = deauth_packets / total_packets
    ic(f"Deauth rate calculated: {deauth_rate}")
    return DeauthRateResponse(
        timestamp=datetime.now().isoformat(),
        deauth_rate=deauth_rate,
        deauth_packets=deauth_packets,
        total_packets=total_packets
    )


@app.get("/statistics/deauth-rate/history", response_model=List[DeauthHistoryResponse])
async def get_deauth_rate_history(
        limit: int = Query(10, description="Number of recent records to retrieve")
) -> List[DeauthHistoryResponse]:
    """
    Endpoint to retrieve the historical deauth rate data.
    Provides the count of deauth packets over the last `limit` records.

    Parameters:
        limit (int): The number of recent records to retrieve (default is 10).

    Returns:
        List[DeauthHistoryResponse]: A list of dictionaries, each containing a timestamp and deauth packet count.
    """
    ic(f"Fetching deauth rate history with limit={limit}")
    # 이력 데이터는 is_deauth=True인 패킷에 대해만 가져온다고 가정
    records = await db.packet.find_many(
        where={"is_deauth": True},
        order={"timestamp": "desc"},
        take=limit
    )
    ic(f"Records fetched: {records}")
    history = [
        DeauthHistoryResponse(timestamp=r.timestamp.isoformat(), count=r.count)
        for r in records
    ]
    ic(f"Formatted history: {history}")
    return history


def sniff_packets(loop: asyncio.AbstractEventLoop) -> None:
    """
    Blocking function that continuously sniffs packets using Scapy.
    For each packet captured, save it to the database (deauth or not).
    """

    def packet_handler(packet: Any) -> None:
        ic("Packet captured", packet.summary())
        if packet.haslayer(Dot11):
            dot11_layer = packet.getlayer(Dot11)
            ic(f"Dot11 Layer - Type: {dot11_layer.type}, Subtype: {dot11_layer.subtype}")
            # Deauth 패킷 판별 로직
            is_deauth = (dot11_layer.type == 0 and dot11_layer.subtype == 12)
            source_mac: str = dot11_layer.addr2 or "Unknown"
            destination_mac: str = dot11_layer.addr1 or "Unknown"
            # 올바른 이벤트 루프 전달
            asyncio.run_coroutine_threadsafe(
                save_packet(source_mac, destination_mac, is_deauth),
                loop
            )
        else:
            # Dot11 레이어가 없을 경우에도 패킷 정보를 저장할 수 있음
            # 단, 여기서는 addr 필드 접근이 불가하므로 Unknown 처리
            asyncio.run_coroutine_threadsafe(
                save_packet("Unknown", "Unknown", False),
                loop
            )

    try:
        # Start sniffing on the specified interface in monitor mode with the packet_handler callback
        sniff(iface="wlx88366cf5c04d", prn=packet_handler, store=0, monitor=True)
        ic("Sniffing completed")
    except Exception as e:
        ic("Error during sniffing", e)


async def save_packet(source_mac: str, destination_mac: str, is_deauth: bool) -> None:
    """
    Saves or updates a packet record in the database.
    If a record with the same source and destination MAC exists, increment the count.
    Otherwise, create a new record.
    """
    ic(f"Saving packet from {source_mac} to {destination_mac}, is_deauth={is_deauth}")
    try:
        record = await db.packet.find_first(
            where={"source_mac": source_mac, "destination_mac": destination_mac, "is_deauth": is_deauth}
        )
        ic("Record fetched from database", record)
        if record:
            await db.packet.update(
                where={"id": record.id},
                data={"count": record.count + 1}
            )
            ic(f"Updated record ID {record.id} with new count {record.count + 1}")
        else:
            await db.packet.create(
                data={
                    "source_mac": source_mac,
                    "destination_mac": destination_mac,
                    "count": 1,
                    "timestamp": datetime.now(),
                    "is_deauth": is_deauth
                }
            )
            ic(f"Created new record for {source_mac} to {destination_mac}")
    except Exception as e:
        ic("Error saving packet", e)
