"""
职责: 提供独立加密样例和回环网络服务以验证通知处理
导出: encrypt_notification, local_push, HTTPService
依赖: cryptography, asyncio, websockets, 仅使用回环网络
约束: 不接触生产端点, 测试负责通过上下文关闭服务
作者: TimeCarol
日期: 2026-10-05 16:42
版本: v1.0
"""

from __future__ import annotations

import asyncio
import secrets
import struct
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Literal

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from websockets.asyncio.server import ServerConnection, serve

from angelic_angel import autopush
from angelic_angel.config import WebPushKeys
from angelic_angel.crypto import encode_base64url


def encrypt_notification(payload: bytes, keys: WebPushKeys, encoding: Literal["aes128gcm", "aesgcm"] = "aes128gcm", padded_plaintext: bytes | None = None) -> tuple[str, dict[str, str]]:
    """独立构造密文以防止解密测试只验证库自身的往返行为

    :param payload: 单条明文, 长度小于 4000 字节
    :param keys: 接收端密钥
    :param encoding: 需要验证的编码格式
    :param padded_plaintext: 故障测试用的已填充明文, None 表示正常填充
    :return: base64url 密文和 AutoPush 头
    :副作用: 生成临时发送端密钥及随机盐, 不访问网络
    """
    sender = ec.generate_private_key(ec.SECP256R1())
    sender_public = sender.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    receiver = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), keys.public_key)
    shared_secret = sender.exchange(ec.ECDH(), receiver)
    salt = secrets.token_bytes(16)
    if encoding == "aes128gcm":
        # RFC 8291 Section 3.4: 两个公钥按接收端, 发送端顺序加入密钥信息
        auth_info = b"WebPush: info\0" + keys.public_key + sender_public
        key_info = b"Content-Encoding: aes128gcm\0"
        nonce_info = b"Content-Encoding: nonce\0"
        padded = payload + b"\x02"
    else:
        # 旧版 Web Push ECE 使用长度前缀上下文和两字节前置填充长度
        context = b"P-256\0" + struct.pack("!H", len(keys.public_key)) + keys.public_key
        context += struct.pack("!H", len(sender_public)) + sender_public
        auth_info = b"Content-Encoding: auth\0"
        key_info = b"Content-Encoding: aesgcm\0" + context
        nonce_info = b"Content-Encoding: nonce\0" + context
        padded = b"\0\0" + payload
    input_key = _derive(shared_secret, keys.auth_secret, auth_info, 32)
    content_key = _derive(input_key, salt, key_info, 16)
    nonce = _derive(input_key, salt, nonce_info, 12)
    encrypted = AESGCM(content_key).encrypt(nonce, padded if padded_plaintext is None else padded_plaintext, None)
    if encoding == "aes128gcm":
        # RFC 8188 Section 2.1: salt(16), rs(4), idlen(1), keyid(65)
        encrypted = salt + struct.pack("!IB", 4096, len(sender_public)) + sender_public + encrypted
        return encode_base64url(encrypted), {"encoding": encoding}
    return encode_base64url(encrypted), {
        "encoding": encoding,
        "crypto_key": f"dh={encode_base64url(sender_public)};p256ecdsa=unused",
        "encryption": f"salt={encode_base64url(salt)}",
    }


def _derive(secret: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """执行标准 HKDF-SHA256 密钥派生

    :param secret: 输入密钥材料
    :param salt: 认证随机数或内容盐
    :param info: 协议规定的上下文
    :param length: 输出字节数
    :return: 派生字节串, 无 IO
    """
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(secret)


@asynccontextmanager
async def local_push(handler: Callable[[ServerConnection], Awaitable[None]], monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[None]:
    """将 AutoPush 调用导向生命周期受限的本地 WebSocket 服务

    :param handler: 单连接异步服务端处理函数
    :param monkeypatch: pytest 临时属性修改管理器
    :return: 服务有效期间的异步上下文
    :副作用: 建立回环监听, 临时替换 AutoPush URL, 退出时关闭服务
    """
    async with serve(handler, "127.0.0.1", 0, ping_interval=None) as server:
        port = server.sockets[0].getsockname()[1]
        monkeypatch.setattr(autopush, "AUTOPUSH_WS_URL", f"ws://127.0.0.1:{port}/")
        yield


@dataclass
class HTTPService:
    """记录回环 HTTP 请求并返回预设状态, 不实现完整 HTTP 服务器

    测试持有可变实例, 仅在同一事件循环使用, 一次连接处理一个请求

    :param url: 测试 fixture 分配的回环 URL
    :param requests: 收到的路径, 头和原始请求体
    :param statuses: 每次请求依次消费的响应状态, 空队列时默认 200
    """

    # fixture 启动后写入, 测试读取, 默认空表示尚未监听
    url: str = ""
    # 服务端处理时追加, 测试只读, 默认空避免跨测试共享数据
    requests: list[tuple[str, dict[str, str], bytes]] = field(default_factory=list)
    # 测试写入, 服务端逐个消费, 默认空表示始终成功
    statuses: deque[int] = field(default_factory=deque)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """记录一个完整 HTTP POST 并关闭连接

        :param reader: 当前连接的异步输入
        :param writer: 当前连接的异步输出
        :return: None 表示响应完成
        :副作用: 修改请求列表和状态队列, 读写并关闭回环连接
        """
        try:
            request_line = (await reader.readline()).decode("ascii").split()
            headers: dict[str, str] = {}
            while (line := await reader.readline()) not in {b"\r\n", b""}:
                name, value = line.decode("latin-1").split(":", 1)
                headers[name.lower()] = value.strip()
            body = await reader.readexactly(int(headers.get("content-length", "0")))
            self.requests.append((request_line[1], headers, body))
            status = self.statuses.popleft() if self.statuses else 200
            response = f"HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n".encode("ascii")
            writer.write(response + b"{}")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
