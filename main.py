from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from scapy.layers.dot11 import Dot11
from prisma import Prisma
from scapy.all import sniff
from typing import List, AsyncGenerator, Any
from datetime import datetime
import asyncio
from pydantic import BaseModel


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
    await startup_event()
    yield
    await shutdown_event()


app = FastAPI(lifespan=lifespan)
db: Prisma = Prisma()

# List of connected WebSocket clients
clients: List[WebSocket] = []


async def startup_event() -> None:
    """
    Event handler for application startup.
    Connects to the database and starts the background task for packet sniffing.
    """
    await db.connect()
    asyncio.create_task(sniff_deauth_packets())


async def shutdown_event() -> None:
    """
    Event handler for application shutdown.
    Disconnects from the database.
    """
    await db.disconnect()


@app.websocket("/stream/deauth-rate")
async def stream_deauth_rate(websocket: WebSocket) -> None:
    """
    WebSocket endpoint to stream deauth packet rate to clients.
    Connects and continuously sends deauth rate updates every 5 seconds.

    Parameters:
        websocket (WebSocket): The WebSocket connection to the client.
    """
    await websocket.accept()
    clients.append(websocket)
    try:
        while True:
            deauth_rate: DeauthRateResponse = await get_deauth_rate()
            await websocket.send_json(deauth_rate.model_dump())
            await asyncio.sleep(5)  # Send every 5 seconds
    except WebSocketDisconnect:
        clients.remove(websocket)


@app.get("/detection/deauth-rate", response_model=DeauthRateResponse)
async def get_deauth_rate() -> DeauthRateResponse:
    """
    Endpoint to retrieve the current rate of deauth packets.

    Returns:
        DeauthRateResponse: A JSON object containing the timestamp, deauth rate, number of deauth packets,
              and the total packet count.
    """
    total_packets: int = await db.deauthpacket.count()
    if total_packets == 0:
        return DeauthRateResponse(
            timestamp=datetime.now().isoformat(),
            deauth_rate=0.0,
            deauth_packets=0,
            total_packets=0
        )

    deauth_packets: int = await db.deauthpacket.count(where={"count": {"gte": 1}})
    deauth_rate: float = deauth_packets / total_packets
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
    records = await db.deauthpacket.find_many(order={"timestamp": "desc"}, take=limit)
    return [
        DeauthHistoryResponse(timestamp=r.timestamp.isoformat(), count=r.count)
        for r in records
    ]


async def sniff_deauth_packets() -> None:
    """
    Background task that continuously sniffs for deauth packets using Scapy.
    Whenever a deauth packet is detected, it triggers the `save_deauth_packet` function.
    """

    def packet_handler(packet: Any) -> None:
        """
        Callback function for handling captured packets.
        Checks if the packet is a deauth packet and, if so, saves it to the database.

        Parameters:
            packet (Any): The captured network packet.
        """
        if packet.haslayer(Dot11):
            # Check if the packet is a deauth frame (type 0, subtype 12)
            if packet.type == 0 and packet.subtype == 12:
                source_mac: str = packet.addr2
                destination_mac: str = packet.addr1
                asyncio.create_task(save_deauth_packet(source_mac, destination_mac))

    # Start sniffing on wlan0mon in monitor mode with the packet_handler callback
    sniff(iface="wlan0mon", prn=packet_handler, store=0, monitor=True)


async def save_deauth_packet(source_mac: str, destination_mac: str) -> None:
    """
    Saves or updates a deauth packet record in the database.
    If a record from the same source and destination MAC already exists, increments the count.
    Otherwise, creates a new record.

    Parameters:
        source_mac (str): The MAC address of the deauth packet sender.
        destination_mac (str): The MAC address of the deauth packet receiver.
    """
    # Check if a record already exists for the given source and destination MAC
    record = await db.deauthpacket.find_first(
        where={"source_mac": source_mac, "destination_mac": destination_mac}
    )
    if record:
        # Update the existing record by incrementing the count
        await db.deauthpacket.update(
            where={"id": record.id},
            data={"count": record.count + 1}
        )
    else:
        # Insert a new record if no matching record exists
        await db.deauthpacket.create(
            data={
                "source_mac": source_mac,
                "destination_mac": destination_mac,
                "count": 1,
                "timestamp": datetime.now()
            }
        )
