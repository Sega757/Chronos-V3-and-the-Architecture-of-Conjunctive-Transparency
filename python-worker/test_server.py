import os
from server import get_bind_addr


def test_get_bind_addr_default(monkeypatch):
    monkeypatch.delenv('WORKER_BIND_ADDR', raising=False)
    assert get_bind_addr() == '127.0.0.1:50052'


def test_get_bind_addr_custom(monkeypatch):
    monkeypatch.setenv('WORKER_BIND_ADDR', '10.0.0.5:50052')
    assert get_bind_addr() == '10.0.0.5:50052'
