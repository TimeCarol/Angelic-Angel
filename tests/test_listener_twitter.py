"""
职责: 验证通知全流程, Twitter/X 注册及监听恢复策略
导出: pytest 测试函数
依赖: 回环 HTTP/WebSocket, 独立加密样例, 少量故障模拟
约束: 不使用真实 Cookie, 重连等待以测试桩替代
作者: TimeCarol
日期: 2026-10-05 16:49
版本: v1.0
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from websockets.asyncio.client import ClientConnection
from websockets.asyncio.server import ServerConnection

from angelic_angel import autopush, listener, twitter
from angelic_angel.autopush import AckCode, AutoPushClient
from angelic_angel.config import Config, Registration, TwitterConfig
from angelic_angel.crypto import encode_base64url
from angelic_angel.errors import AutoPushError, HTTPError, ReregistrationError, ServerBackoffError, TwitterAPIError
from angelic_angel.listener import SessionOutcome, SessionState
from angelic_angel.push import generate_keys
from tests.helpers import HTTPService, encrypt_notification, local_push


@pytest.mark.parametrize("http_service", ["http", "https"], indirect=True)
async def test_notifications_forward_unicode_and_correct_ack(registration: Registration, http_service: HTTPService, monkeypatch: pytest.MonkeyPatch) -> None:
    """验证 HTTP 和自签名 HTTPS 的中文转发及所有通知 ACK

    :param registration: 测试订阅和密钥
    :param http_service: 记录 webhook 的回环 HTTP 服务
    :param monkeypatch: 临时替换生产端点和 webhook 环境变量
    :return: None, 断言失败表示完整交付流程不符合约定
    """
    monkeypatch.setenv("WEBHOOK_ENDPOINT", http_service.url + "/hook")
    modern_data, modern_headers = encrypt_notification(json.dumps({"text": "中文通知 🌸"}, ensure_ascii=False).encode(), registration.keys)
    legacy_data, legacy_headers = encrypt_notification("纯文本通知".encode(), registration.keys, "aesgcm")
    invalid_utf8, utf8_headers = encrypt_notification(b"\xff", registration.keys)
    # 第二个 HTTP 响应故意为 500, 验证已有响应时仍使用 ACK 100 的交付约定
    http_service.statuses.extend([200, 500])
    payloads = [
        ("中文JSON", modern_data, modern_headers),
        ("旧格式", legacy_data, legacy_headers),
        ("坏密文", "%invalid", None),
        ("坏UTF-8", invalid_utf8, utf8_headers),
        ("空消息", None, None),
    ]
    acknowledgements: list[dict[str, object]] = []
    ack_texts: list[str] = []

    async def handler(websocket: ServerConnection) -> None:
        """发送不同失败场景的通知并记录实际 ACK 文本

        :param websocket: 回环连接
        :return: None, 每条通知收到 ACK 后才发送下一条
        """
        await websocket.recv()
        await websocket.send(json.dumps({"messageType": "hello", "status": 200, "uaid": "test-uaid"}, ensure_ascii=False))
        for version, data, headers in payloads:
            await websocket.send(json.dumps({
                "messageType": "notification", "channelID": "test-channel", "version": version,
                "data": data, "headers": headers,
            }, ensure_ascii=False))
            ack = await websocket.recv()
            assert isinstance(ack, str)
            ack_texts.append(ack)
            acknowledgements.append(cast(dict[str, object], json.loads(ack)))

    async with local_push(handler, monkeypatch):
        client = await autopush.connect_and_listen(registration.autopush, registration.keys)
        assert isinstance(client, AutoPushClient)
        try:
            await asyncio.wait_for(listener.run_notification_loop(client, registration), 5)
        finally:
            await client.close()
    updates = [cast(list[dict[str, object]], message["updates"])[0] for message in acknowledgements]
    assert [update["code"] for update in updates] == [100, 100, 101, 101, 100]
    assert "中文JSON" in ack_texts[0] and "\\u" not in ack_texts[0]
    assert len(http_service.requests) == 2
    assert json.loads(http_service.requests[0][2]) == {"text": "中文通知 🌸"}
    assert "中文通知 🌸".encode() in http_service.requests[0][2]
    assert b"\\u" not in http_service.requests[0][2]
    assert json.loads(http_service.requests[1][2]) == {"raw": "纯文本通知"}


async def test_webhook_transport_failure_returns_ack102(registration: Registration, monkeypatch: pytest.MonkeyPatch) -> None:
    """验证解密成功但 webhook 传输失败对应 ACK 102

    :param registration: 测试密钥
    :param monkeypatch: 设置虚构 webhook 地址
    :return: None, 断言失败表示传输失败被误报为解密失败
    """
    monkeypatch.setenv("WEBHOOK_ENDPOINT", "https://webhook.example.test")

    async def offline(request: httpx.Request) -> httpx.Response:
        """模拟对指定 webhook 的连接失败

        :param request: 待发送请求
        :raises httpx.ConnectError: 始终拒绝连接, 不访问网络
        """
        raise httpx.ConnectError("test connection refused", request=request)

    data, headers = encrypt_notification(b'{"message":"ok"}', registration.keys)
    async with httpx.AsyncClient(transport=httpx.MockTransport(offline)) as client:
        assert await listener._process_data(data, headers, registration.keys, client) is AckCode.NOT_DELIVERED


async def test_missing_webhook_returns_ack102(registration: Registration, monkeypatch: pytest.MonkeyPatch) -> None:
    """验证缺少 webhook 设置时仍确认其他处理失败

    :param registration: 测试密钥
    :param monkeypatch: 移除环境变量
    :return: None, 断言失败表示配置错误中断整个通知循环
    """
    monkeypatch.delenv("WEBHOOK_ENDPOINT", raising=False)
    data, headers = encrypt_notification(b"valid text", registration.keys)
    async with httpx.AsyncClient() as client:
        assert await listener._process_data(data, headers, registration.keys, client) is AckCode.NOT_DELIVERED


async def test_twitter_request_contains_subscription_keys(registration: Registration, http_service: HTTPService, monkeypatch: pytest.MonkeyPatch, signed_headers: None) -> None:
    """验证 Twitter/X 注册请求路径, Cookie 和密钥编码

    :param registration: 完整订阅
    :param http_service: 回环 HTTP 服务
    :param monkeypatch: 替换 Twitter/X API 地址
    :param signed_headers: 固定签名以隔离 Web 页面网络请求
    :return: None, 断言失败表示注册请求结构错误
    """
    monkeypatch.setattr(twitter, "TWITTER_API_BASE", http_service.url + "/i/api/1.1")
    await twitter.register(TwitterConfig("test-token", "test-csrf"), registration)
    path, headers, body = http_service.requests[0]
    assert path == "/i/api/1.1/notifications/settings/login.json"
    assert headers["x-csrf-token"] == "test-csrf"
    assert headers["cookie"] == "auth_token=test-token; ct0=test-csrf"
    assert headers["x-twitter-auth-type"] == "OAuth2Session"
    assert headers["x-client-transaction-id"] == "test-transaction"
    device = json.loads(body)["push_device_info"]
    assert device["token"] == registration.endpoint
    assert device["encryption_key1"] == encode_base64url(registration.keys.public_key)
    assert device["encryption_key2"] == encode_base64url(registration.keys.auth_secret)
    assert device["env"] == 3


async def test_twitter_non_success_has_status_context(registration: Registration, http_service: HTTPService, monkeypatch: pytest.MonkeyPatch, signed_headers: None) -> None:
    """验证注册被拒绝时异常保留 HTTP 状态

    :param registration: 完整订阅
    :param http_service: 回环 HTTP 服务
    :param monkeypatch: 替换 Twitter/X 地址
    :param signed_headers: 固定签名以隔离 Web 页面网络请求
    :return: None, 断言失败表示拒绝响应被当作成功
    """
    monkeypatch.setattr(twitter, "TWITTER_API_BASE", http_service.url)
    http_service.statuses.append(403)
    with pytest.raises(TwitterAPIError, match="403"):
        await twitter.register(TwitterConfig("token", "csrf"), registration)


async def test_invalid_twitter_url_is_application_error(registration: Registration, monkeypatch: pytest.MonkeyPatch, signed_headers: None) -> None:
    """验证注册 URL 错误可由应用统一处理

    :param registration: 完整订阅
    :param monkeypatch: 注入无效 URL
    :param signed_headers: 固定签名以隔离 Web 页面网络请求
    :return: None, 断言失败表示 HTTP 库异常直接泄漏
    """
    monkeypatch.setattr(twitter, "TWITTER_API_BASE", "://invalid")
    with pytest.raises(HTTPError):
        await twitter.register(TwitterConfig("token", "csrf"), registration)


async def test_signed_headers_refresh_csrf_without_leaking_cookies(monkeypatch: pytest.MonkeyPatch) -> None:
    """验证签名使用当前 CSRF 且静态脚本请求不携带会话 Cookie

    :param monkeypatch: 替换签名算法以单独验证请求边界
    :return: None, 断言失败表示签名路径或 Cookie 域隔离错误
    """
    received: list[httpx.Request] = []
    generator = Mock()
    generator.generate_transaction_id.return_value = "signed-transaction"
    monkeypatch.setattr(twitter, "ClientTransaction", Mock(return_value=generator))
    monkeypatch.setattr(twitter, "get_ondemand_file_url", Mock(return_value="https://static.example.test/transaction.js"))

    async def handler(request: httpx.Request) -> httpx.Response:
        """模拟首页刷新 Cookie 及外部静态脚本

        :param request: 待发送 HTTP 请求
        :return: 首页或脚本的成功响应, 不访问网络
        """
        received.append(request)
        if request.url.host == "x.com":
            return httpx.Response(200, text="<html></html>", headers={"Set-Cookie": "ct0=refreshed-csrf; Domain=x.com; Path=/"})
        return httpx.Response(200, text="test-script")

    path = "/i/api/1.1/notifications/settings/login.json"
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        headers = await twitter._prepare_signed_headers(client, TwitterConfig("secret-token", "old-csrf"), path)
    assert received[0].headers["cookie"] == "auth_token=secret-token; ct0=old-csrf"
    assert "cookie" not in received[1].headers
    assert headers["x-csrf-token"] == "refreshed-csrf"
    assert headers["Cookie"] == "auth_token=secret-token; ct0=refreshed-csrf"
    assert headers["x-client-transaction-id"] == "signed-transaction"
    generator.generate_transaction_id.assert_called_once_with(method="POST", path=path)


async def test_invalid_signature_material_is_application_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """验证签名页面缺失必要材料时报告可定位应用错误

    :param monkeypatch: 模拟签名 URL 无法解析
    :return: None, 断言失败表示签名异常直接泄漏到 CLI
    """
    monkeypatch.setattr(twitter, "get_ondemand_file_url", Mock(side_effect=ValueError("missing script")))
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text="<html></html>"))
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(HTTPError, match="request signature"):
            await twitter._prepare_signed_headers(client, TwitterConfig("token", "csrf"), "/login.json")


async def test_reregistration_persists_new_keys_before_reconnect(config_path: Path, registration: Registration, monkeypatch: pytest.MonkeyPatch) -> None:
    """验证 UAID 恢复将新订阅同步到 Twitter/X 及配置后再连接

    :param config_path: 已保存的旧订阅
    :param registration: 旧订阅
    :param monkeypatch: 模拟恢复所需的网络调用
    :return: None, 断言失败表示新密钥没有持久化或被错误连接
    """
    new_registration = replace(registration, keys=generate_keys(), endpoint="https://push.example.test/new")
    connected = AutoPushClient(cast(ClientConnection, AsyncMock()), new_registration.autopush)
    connect = AsyncMock(side_effect=[new_registration, connected])
    register = AsyncMock()
    monkeypatch.setattr(autopush, "connect_and_listen", connect)
    monkeypatch.setattr(twitter, "register", register)
    client, updated = await listener._try_connect(registration, config_path)
    assert client is connected and updated == new_registration
    assert Config.load(config_path).registration == new_registration
    register.assert_awaited_once_with(Config.load(config_path).twitter, new_registration)
    assert connect.await_args_list[1].args == (new_registration.autopush, new_registration.keys)


async def test_failed_uaid_recovery_is_fatal_and_keeps_config(config_path: Path, registration: Registration, monkeypatch: pytest.MonkeyPatch) -> None:
    """验证 Twitter/X 拒绝恢复时不覆盖旧配置并标记终止错误

    :param config_path: 已保存配置
    :param registration: 旧订阅
    :param monkeypatch: 模拟恢复注册被拒绝
    :return: None, 断言失败表示无效订阅覆盖此前配置
    """
    before = config_path.read_bytes()
    replacement = replace(registration, keys=generate_keys())
    monkeypatch.setattr(autopush, "connect_and_listen", AsyncMock(return_value=replacement))
    monkeypatch.setattr(twitter, "register", AsyncMock(side_effect=TwitterAPIError("rejected")))
    outcome = await listener._listen_once(registration, config_path)
    assert outcome.state is SessionState.FATAL
    assert isinstance(outcome.error, ReregistrationError)
    assert config_path.read_bytes() == before


async def test_second_uaid_invalidation_is_fatal(config_path: Path, registration: Registration, monkeypatch: pytest.MonkeyPatch) -> None:
    """验证恢复后仍失效不会进入不断重注册的循环

    :param config_path: 已保存配置
    :param registration: 测试订阅
    :param monkeypatch: 两次连接均返回新订阅
    :return: None, 断言失败表示恢复失败被误当作普通连接失败
    """
    monkeypatch.setattr(autopush, "connect_and_listen", AsyncMock(return_value=registration))
    monkeypatch.setattr(twitter, "register", AsyncMock())
    with pytest.raises(ReregistrationError, match="still failed"):
        await listener._try_connect(registration, config_path)


@pytest.mark.parametrize("retry_count, expected", [(0, 5), (1, 5), (2, 10), (3, 20), (6, 160), (7, 300), (1000000, 300)])
def test_backoff_sequence_and_large_count(retry_count: int, expected: int) -> None:
    """验证首次等待, 指数增长和巨大计数的上限

    :param retry_count: 连续失败次数
    :param expected: 预期等待秒数
    :return: None, 断言失败表示重试调度偏离约定
    """
    assert listener.calc_backoff(retry_count) == expected


async def test_reconnect_resets_retry_and_obeys_server_backoff(config_path: Path, registration: Registration, monkeypatch: pytest.MonkeyPatch) -> None:
    """验证成功连接后重置指数计数且服务端退避优先

    :param config_path: 测试配置
    :param registration: 测试订阅
    :param monkeypatch: 替换单次会话和等待以验证调度
    :return: None, 断言失败表示恢复延迟错误
    """
    outcomes = [
        SessionOutcome(SessionState.CONNECTION_FAILED, registration, AutoPushError("offline")),
        SessionOutcome(SessionState.CONNECTION_FAILED, registration, AutoPushError("offline")),
        SessionOutcome(SessionState.NORMAL_CLOSE, registration),
        SessionOutcome(SessionState.CONNECTION_FAILED, registration, AutoPushError("offline")),
        SessionOutcome(SessionState.DISCONNECTED, registration, ServerBackoffError("backoff")),
        SessionOutcome(SessionState.CONNECTION_FAILED, registration, AutoPushError("offline")),
        SessionOutcome(SessionState.DISCONNECTED, registration, AutoPushError("disconnected")),
        SessionOutcome(SessionState.CONNECTION_FAILED, registration, AutoPushError("offline")),
    ]
    delays: list[float] = []

    async def record_delay(delay: float) -> None:
        """记录等待并在完成全部调度样例后取消监听

        :param delay: listener 计算的秒数
        :raises asyncio.CancelledError: 记录最后一次等待后终止测试循环
        """
        delays.append(delay)
        if len(delays) == len(outcomes):
            raise asyncio.CancelledError

    monkeypatch.setattr(listener, "_listen_once", AsyncMock(side_effect=outcomes))
    monkeypatch.setattr("angelic_angel.listener.asyncio.sleep", record_delay)
    with pytest.raises(asyncio.CancelledError):
        await listener.listen(registration, config_path)
    assert delays == [5, 10, 1, 5, 1800, 5, 1, 5]


async def test_fatal_session_stops_retries(config_path: Path, registration: Registration, monkeypatch: pytest.MonkeyPatch) -> None:
    """验证不可恢复订阅错误直接终止监听

    :param config_path: 测试配置
    :param registration: 测试订阅
    :param monkeypatch: 注入不可恢复的会话结果
    :return: None, 断言失败表示终止错误被无限重试
    """
    failure = ReregistrationError("recovery rejected")
    monkeypatch.setattr(listener, "_listen_once", AsyncMock(return_value=SessionOutcome(SessionState.FATAL, registration, failure)))
    with pytest.raises(ReregistrationError, match="recovery rejected"):
        await listener.listen(registration, config_path)
