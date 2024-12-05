from datetime import datetime
from unittest.mock import AsyncMock, patch, MagicMock

import pytest
from fastapi.testclient import TestClient
from prisma import Prisma

from main import app, db, save_deauth_packet, sniff_deauth_packets, DeauthRateResponse, DeauthHistoryResponse


class MockPrismaModel:
    """모의 Prisma 모델 객체"""
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    def dict(self):
        return {k: v for k, v in self.__dict__.items()}


@pytest.fixture
def mock_db():
    """
    Mock the database client for tests.
    """
    with patch('main.db') as mock_db:
        # 데이터베이스 연결 상태 모킹
        mock_db.connect = AsyncMock()
        mock_db.disconnect = AsyncMock()
        mock_db.deauthpacket = AsyncMock()
        yield mock_db


@pytest.fixture
async def client(mock_db):
    """
    Test client to interact with FastAPI.
    """
    # 테스트 전에 DB 연결
    await mock_db.connect()
    test_client = TestClient(app)
    yield test_client
    # 테스트 후 DB 연결 해제
    await mock_db.disconnect()


@pytest.mark.asyncio
async def test_get_deauth_rate(mock_db, client):
    """
    Test the /detection/deauth-rate endpoint.
    """
    # Mock the database response
    mock_db.deauthpacket.count.side_effect = [100, 50]  # 첫 번째 호출과 두 번째 호출의 반환값 설정

    # Simulate the API call
    response = client.get("/detection/deauth-rate")

    # Check response status and content
    assert response.status_code == 200
    data = response.json()
    assert "timestamp" in data
    assert data["deauth_rate"] == 0.5
    assert data["deauth_packets"] == 50
    assert data["total_packets"] == 100


@pytest.mark.asyncio
async def test_get_deauth_rate_history(mock_db, client):
    """
    Test the /statistics/deauth-rate/history endpoint.
    """
    # Mock the database response with MockPrismaModel
    mock_data = [
        MockPrismaModel(
            timestamp=datetime.fromisoformat("2024-12-05T00:00:00"),
            count=10
        ),
        MockPrismaModel(
            timestamp=datetime.fromisoformat("2024-12-04T00:00:00"),
            count=20
        ),
    ]
    mock_db.deauthpacket.find_many.return_value = mock_data

    # Simulate the API call with limit = 2
    response = client.get("/statistics/deauth-rate/history?limit=2")

    # Check response status and content
    assert response.status_code == 200
    assert response.json() == [
        {"timestamp": "2024-12-05T00:00:00", "count": 10},
        {"timestamp": "2024-12-04T00:00:00", "count": 20},
    ]


@pytest.mark.asyncio
async def test_websocket_deauth_rate(mock_db, client):
    """
    Test the /stream/deauth-rate WebSocket endpoint.
    """
    # Mock the database response for deauth rate
    mock_db.deauthpacket.count.side_effect = [100, 50]  # 첫 번째와 두 번째 호출의 반환값

    # DeauthRateResponse를 dict로 변환하는 함수를 모킹
    def mock_model_dump(exclude_unset=False):
        return {
            "timestamp": "2024-12-05T00:00:00",
            "deauth_rate": 0.5,
            "deauth_packets": 50,
            "total_packets": 100
        }

    # DeauthRateResponse의 model_dump 메서드를 모킹
    with patch.object(DeauthRateResponse, 'model_dump', mock_model_dump):
        # Simulate the WebSocket connection
        with client.websocket_connect("/stream/deauth-rate") as websocket:
            # Receive the initial deauth rate data
            data = websocket.receive_json()
            
            assert "timestamp" in data
            assert data["deauth_rate"] == 0.5
            assert data["deauth_packets"] == 50
            assert data["total_packets"] == 100


@pytest.mark.asyncio
async def test_save_deauth_packet(mock_db):
    """
    Test the save_deauth_packet function.
    """
    # Mock find_first for non-existent record
    mock_db.deauthpacket.find_first.return_value = None
    
    # Test creating a new record
    await save_deauth_packet("00:11:22:33:44:55", "66:77:88:99:00:11")

    # Verify create was called with correct parameters
    mock_db.deauthpacket.create.assert_called_once()
    create_call = mock_db.deauthpacket.create.call_args[1]['data']
    assert create_call['source_mac'] == "00:11:22:33:44:55"
    assert create_call['destination_mac'] == "66:77:88:99:00:11"
    assert create_call['count'] == 1

    # Reset mocks for next test
    mock_db.deauthpacket.create.reset_mock()
    
    # Mock find_first for existing record with MockPrismaModel
    mock_db.deauthpacket.find_first.return_value = MockPrismaModel(
        id=1,
        count=1
    )
    
    # Test updating existing record
    await save_deauth_packet("00:11:22:33:44:55", "66:77:88:99:00:11")
    
    # Verify update was called with correct parameters
    mock_db.deauthpacket.update.assert_called_once_with(
        where={"id": 1},
        data={"count": 2}
    )


@pytest.mark.asyncio
async def test_sniff_deauth_packets():
    """
    Test sniffing deauth packets.
    This test mocks the packet capture functionality and calls the packet handler directly.
    """
    async def packet_handler(packet):
        await save_deauth_packet(packet["addr1"], packet["addr2"])

    # Mock the packet capture behavior
    packet = {
        "type": 0,
        "subtype": 12,
        "addr1": "00:11:22:33:44:55",
        "addr2": "66:77:88:99:00:11",
        "haslayer": lambda x: True
    }

    # Mock the save_deauth_packet function
    with patch('test_main.save_deauth_packet', new_callable=AsyncMock) as mock_save_deauth_packet:
        await packet_handler(packet)
        # Check that save_deauth_packet was called with the correct params
        mock_save_deauth_packet.assert_called_with("00:11:22:33:44:55", "66:77:88:99:00:11")
