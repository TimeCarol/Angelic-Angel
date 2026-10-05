"""
职责: 创建独立的配置和回环 HTTP/HTTPS 测试环境
导出: registration, config_path, http_service fixtures
依赖: pytest, asyncio, cryptography, 临时证书文件和回环网络
约束: 每个测试重新生成密钥和配置, 不读取真实凭据
作者: TimeCarol
日期: 2026-10-05 16:42
版本: v1.0
"""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509.oid import NameOID

from angelic_angel import twitter
from angelic_angel.config import AutoPushSession, Config, Registration, TwitterConfig
from angelic_angel.push import generate_keys
from tests.helpers import HTTPService


@pytest.fixture
def registration() -> Registration:
    """创建不关联生产服务的订阅

    :return: 新密钥及固定测试标识, 不访问网络
    """
    return Registration("https://push.example.test/endpoint", AutoPushSession("test-uaid", "test-channel"), generate_keys())


@pytest.fixture
def signed_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    """隔离普通注册测试中的签名材料网络读取

    :param monkeypatch: pytest 临时属性替换
    :return: None, 返回固定签名以便独立验证 HTTP 注册请求
    """
    monkeypatch.setattr(twitter, "_prepare_signed_headers", AsyncMock(return_value={"x-client-transaction-id": "test-transaction"}))


@pytest.fixture
def config_path(tmp_path: Path, registration: Registration) -> Path:
    """保存仅含虚构凭据的测试配置

    :param tmp_path: pytest 管理的临时目录
    :param registration: 独立测试订阅
    :return: 已写入的 TOML 文件路径, 测试后由 pytest 清理
    """
    path = tmp_path / "config.toml"
    Config(TwitterConfig("test-auth-token", "test-csrf-token"), registration).save(path)
    return path


@pytest_asyncio.fixture
async def http_service(request: pytest.FixtureRequest, tmp_path: Path) -> AsyncIterator[HTTPService]:
    """创建记录实际 HTTP 或自签名 HTTPS 请求的回环服务

    :param request: 通过间接参数选择 http 或 https, 缺省为 http
    :param tmp_path: 自签名证书的临时保存目录
    :return: 生命周期限制在测试内的服务, 退出时关闭监听
    """
    service = HTTPService()
    is_https = getattr(request, "param", "http") == "https"
    context = _self_signed_context(tmp_path) if is_https else None
    server = await asyncio.start_server(service.handle, "127.0.0.1", 0, ssl=context)
    port = server.sockets[0].getsockname()[1]
    service.url = f"{'https' if is_https else 'http'}://127.0.0.1:{port}"
    async with server:
        yield service


def _self_signed_context(tmp_path: Path) -> ssl.SSLContext:
    """生成系统不信任的临时证书以验证 webhook 的 SSL 行为

    :param tmp_path: pytest 管理的临时目录
    :return: 仅用于回环服务器的 TLS 上下文
    :副作用: 写入临时 PEM 证书和私钥, 不修改系统信任证书
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(private_key, hashes.SHA256())
    )
    certificate_path = tmp_path / "localhost.pem"
    private_key_path = tmp_path / "localhost-key.pem"
    certificate_path.write_bytes(certificate.public_bytes(Encoding.PEM))
    private_key_path.write_bytes(private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate_path, private_key_path)
    return context
