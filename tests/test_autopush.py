"""
职责: 用真实回环 WebSocket 验证 AutoPush 协议及连接生命周期
导出: pytest 测试函数
依赖: asyncio, websockets, 临时属性替换
约束: 超时使用缩短的测试间隔, 不连接生产推送服务
作者: TimeCarol
日期: 2026-10-05 16:45
版本: v1.0
"""

from __future__ import annotations

import asyncio
import json
from typing import cast

import pytest
from websockets.asyncio.server import ServerConnection

from angelic_angel import autopush
from angelic_angel.autopush import AckCode, AutoPushClient
from angelic_angel.config import Registration
from angelic_angel.crypto import encode_base64url
from angelic_angel.errors import AutoPushError, ServerBackoffError
from tests.helpers import local_push


async def _accept_hello(websocket: ServerConnection, uaid: str = "test-uaid") -> dict[str, object]:
    """回复成功 hello 并返回客户端请求

    :param websocket: 本地测试连接
    :param uaid: 本次响应的用户标识
    :return: 客户端 hello 请求, 副作用为读写一次连接
    """
    request = cast(dict[str, object], json.loads(await websocket.recv()))
    await websocket.send(json.dumps({"messageType": "hello", "status": 200, "uaid": uaid}, ensure_ascii=False))
    return request


async def test_registration_uses_vapid_and_firefox_hello(registration: Registration, monkeypatch: pytest.MonkeyPatch) -> None:
    """验证注册握手格式, VAPID 公钥及返回订阅

    :param registration: 接收端密钥
    :param monkeypatch: 将地址替换为回环服务
    :return: None, 断言失败表示协议字段不符合要求
    """
    received: list[dict[str, object]] = []

    async def handler(websocket: ServerConnection) -> None:
        """记录注册请求并返回 endpoint

        :param websocket: 回环连接
        :return: None, 关闭事件由客户端触发
        """
        received.append(await _accept_hello(websocket, "new-uaid"))
        request = cast(dict[str, object], json.loads(await websocket.recv()))
        received.append(request)
        await websocket.send(json.dumps({
            "messageType": "register", "status": 200, "channelID": request["channelID"],
            "pushEndpoint": "https://push.example.test/new",
        }, ensure_ascii=False))
        await websocket.wait_closed()

    async with local_push(handler, monkeypatch):
        result = await autopush.register_new(registration.keys)
    assert result.autopush.uaid == "new-uaid"
    assert result.endpoint == "https://push.example.test/new"
    assert result.keys == registration.keys
    assert received[0] == {"messageType": "hello", "uaid": "", "use_webpush": True, "broadcasts": {}}
    assert received[1]["key"] == encode_base64url(autopush.TWITTER_VAPID_PUBLIC_KEY)
    assert received[1]["channelID"] == result.autopush.channel_id


async def test_uaid_change_returns_fresh_keys(registration: Registration, monkeypatch: pytest.MonkeyPatch) -> None:
    """验证 UAID 改变时关闭失效连接并新建订阅密钥

    :param registration: 失效的旧订阅
    :param monkeypatch: 回环服务地址替换
    :return: None, 断言失败表示失效密钥被复用
    """
    hellos: list[dict[str, object]] = []

    async def handler(websocket: ServerConnection) -> None:
        """让旧 UAID 失效并响应随后的新通道注册

        :param websocket: 回环连接
        :return: None, 连接由调用方关闭
        """
        request = await _accept_hello(websocket, "replacement-uaid")
        hellos.append(request)
        if request["uaid"]:
            await websocket.wait_closed()
            return
        register = cast(dict[str, object], json.loads(await websocket.recv()))
        await websocket.send(json.dumps({
            "messageType": "register", "status": 200, "channelID": register["channelID"],
            "pushEndpoint": "https://push.example.test/replacement",
        }, ensure_ascii=False))
        await websocket.wait_closed()

    async with local_push(handler, monkeypatch):
        result = await autopush.connect_and_listen(registration.autopush, registration.keys)
    assert isinstance(result, Registration)
    assert result.keys.private_key != registration.keys.private_key
    assert result.keys.auth_secret != registration.keys.auth_secret
    assert [request["uaid"] for request in hellos] == ["test-uaid", ""]


async def test_duplicate_notification_is_acked_without_redelivery(registration: Registration, monkeypatch: pytest.MonkeyPatch) -> None:
    """验证重复版本只自动确认而不再次交付

    :param registration: 已有会话
    :param monkeypatch: 回环地址替换
    :return: None, 断言失败表示重复通知被交付两次
    """
    acknowledgements: list[dict[str, object]] = []

    async def handler(websocket: ServerConnection) -> None:
        """发送两个相同版本并记录两次 ACK

        :param websocket: 回环连接
        :return: None, 最后由服务端正常关闭
        """
        await _accept_hello(websocket)
        message = json.dumps({"messageType": "notification", "channelID": "test-channel", "version": "one"}, ensure_ascii=False)
        await websocket.send(message)
        acknowledgements.append(cast(dict[str, object], json.loads(await websocket.recv())))
        await websocket.send(message)
        acknowledgements.append(cast(dict[str, object], json.loads(await websocket.recv())))

    async with local_push(handler, monkeypatch):
        client = await autopush.connect_and_listen(registration.autopush, registration.keys)
        assert isinstance(client, AutoPushClient)
        try:
            notification = await client.next_notification()
            assert notification is not None and notification.version == "one"
            await client.ack_notification(notification.channel_id, notification.version, AckCode.DELIVERED)
            assert await client.next_notification() is None
        finally:
            await client.close()
    assert len(acknowledgements) == 2
    assert acknowledgements[1]["updates"] == [{"channelID": "test-channel", "version": "one", "code": 100}]


async def test_duplicate_cache_evicts_oldest_version(registration: Registration, monkeypatch: pytest.MonkeyPatch) -> None:
    """验证最近 100 条通知之外的版本可以再次交付

    :param registration: 已有会话
    :param monkeypatch: 回环地址替换
    :return: None, 断言失败表示缓存无限增长或淘汰错误
    """
    versions = [str(index) for index in range(101)] + ["0"]

    async def handler(websocket: ServerConnection) -> None:
        """发送超出缓存容量的不同版本再重发最旧版本

        :param websocket: 回环连接
        :return: None, 发送完成后正常关闭
        """
        await _accept_hello(websocket)
        for version in versions:
            await websocket.send(json.dumps({"messageType": "notification", "channelID": "test-channel", "version": version}, ensure_ascii=False))

    delivered: list[str] = []
    async with local_push(handler, monkeypatch):
        client = await autopush.connect_and_listen(registration.autopush, registration.keys)
        assert isinstance(client, AutoPushClient)
        try:
            while (notification := await client.next_notification()) is not None:
                delivered.append(notification.version)
        finally:
            await client.close()
    assert delivered == versions


async def test_application_ping_receives_pong(registration: Registration, monkeypatch: pytest.MonkeyPatch) -> None:
    """验证空闲连接发送应用 ping 并接受空 JSON pong

    :param registration: 已有会话
    :param monkeypatch: 缩短心跳和替换回环地址
    :return: None, 断言失败表示心跳或后续通知丢失
    """
    monkeypatch.setattr(autopush, "PING_INTERVAL_SECS", 0.02)
    received: list[str | bytes] = []

    async def handler(websocket: ServerConnection) -> None:
        """回复应用 pong 后发送一条通知

        :param websocket: 回环连接
        :return: None, 通知发送完毕后正常关闭
        """
        await _accept_hello(websocket)
        received.append(await websocket.recv())
        await websocket.send("{}")
        await websocket.send(json.dumps({"messageType": "notification", "channelID": "test-channel", "version": "after-pong"}, ensure_ascii=False))

    async with local_push(handler, monkeypatch):
        client = await autopush.connect_and_listen(registration.autopush, registration.keys)
        assert isinstance(client, AutoPushClient)
        try:
            notification = await asyncio.wait_for(client.next_notification(), 1)
            assert notification is not None and notification.version == "after-pong"
        finally:
            await client.close()
    assert received == ["{}"]


async def test_notification_during_pong_wait_is_not_lost(registration: Registration, monkeypatch: pytest.MonkeyPatch) -> None:
    """验证等待 pong 时收到的通知仍正常交付

    :param registration: 已有会话
    :param monkeypatch: 缩短心跳和替换地址
    :return: None, 断言失败表示等待 pong 吞掉通知
    """
    monkeypatch.setattr(autopush, "PING_INTERVAL_SECS", 0.02)

    async def handler(websocket: ServerConnection) -> None:
        """直接用通知响应应用 ping

        :param websocket: 回环连接
        :return: None, 发完两条通知后正常关闭
        """
        await _accept_hello(websocket)
        assert await websocket.recv() == "{}"
        for version in ["during-pong", "next"]:
            await websocket.send(json.dumps({"messageType": "notification", "channelID": "test-channel", "version": version}, ensure_ascii=False))

    async with local_push(handler, monkeypatch):
        client = await autopush.connect_and_listen(registration.autopush, registration.keys)
        assert isinstance(client, AutoPushClient)
        try:
            first = await client.next_notification()
            second = await client.next_notification()
            assert first is not None and first.version == "during-pong"
            assert second is not None and second.version == "next"
        finally:
            await client.close()


async def test_missing_application_pong_times_out(registration: Registration, monkeypatch: pytest.MonkeyPatch) -> None:
    """验证服务端不响应应用 ping 时要求重连

    :param registration: 已有会话
    :param monkeypatch: 缩短测试超时并替换地址
    :return: None, 断言失败表示静默失联不能被检测
    """
    monkeypatch.setattr(autopush, "PING_INTERVAL_SECS", 0.02)
    monkeypatch.setattr(autopush, "PONG_TIMEOUT_SECS", 0.05)

    async def handler(websocket: ServerConnection) -> None:
        """故意不回复应用 ping

        :param websocket: 回环连接
        :return: None, 等待客户端检测超时并关闭
        """
        await _accept_hello(websocket)
        await websocket.recv()
        await websocket.wait_closed()

    async with local_push(handler, monkeypatch):
        client = await autopush.connect_and_listen(registration.autopush, registration.keys)
        assert isinstance(client, AutoPushClient)
        try:
            with pytest.raises(AutoPushError, match="pong timed out"):
                await client.next_notification()
        finally:
            await client.close()


async def test_server_backoff_close_is_distinct(registration: Registration, monkeypatch: pytest.MonkeyPatch) -> None:
    """验证关闭码 4774 被识别为服务器退避

    :param registration: 已有会话
    :param monkeypatch: 回环地址替换
    :return: None, 断言失败表示服务端退避被当作普通关闭
    """
    async def handler(websocket: ServerConnection) -> None:
        """发送服务器退避关闭帧

        :param websocket: 回环连接
        :return: None, 关闭码用于验证恢复策略
        """
        await _accept_hello(websocket)
        await websocket.close(code=4774)

    async with local_push(handler, monkeypatch):
        client = await autopush.connect_and_listen(registration.autopush, registration.keys)
        assert isinstance(client, AutoPushClient)
        try:
            with pytest.raises(ServerBackoffError):
                await client.next_notification()
        finally:
            await client.close()


async def test_hello_timeout_closes_connection(registration: Registration, monkeypatch: pytest.MonkeyPatch) -> None:
    """验证 hello 无响应会超时且不会遗留连接

    :param registration: 新订阅密钥
    :param monkeypatch: 缩短握手超时和替换地址
    :return: None, 断言失败表示超时连接未释放
    """
    monkeypatch.setattr(autopush, "PONG_TIMEOUT_SECS", 0.05)
    closed = asyncio.Event()

    async def handler(websocket: ServerConnection) -> None:
        """收到 hello 后保持静默以触发超时

        :param websocket: 回环连接
        :return: None, 关闭完成后设置同步事件
        """
        await websocket.recv()
        await websocket.wait_closed()
        closed.set()

    async with local_push(handler, monkeypatch):
        with pytest.raises(AutoPushError, match="hello response timed out"):
            await autopush.register_new(registration.keys)
        await asyncio.wait_for(closed.wait(), 1)


async def test_unregister_sends_channel_and_code(registration: Registration, monkeypatch: pytest.MonkeyPatch) -> None:
    """验证注销包含保存的通道和正常注销代码

    :param registration: 待注销订阅
    :param monkeypatch: 回环地址替换
    :return: None, 断言失败表示注销目标或代码错误
    """
    received: list[dict[str, object]] = []

    async def handler(websocket: ServerConnection) -> None:
        """记录 hello 和注销请求

        :param websocket: 回环连接
        :return: None, 请求记录后等待客户端关闭
        """
        received.append(await _accept_hello(websocket))
        received.append(cast(dict[str, object], json.loads(await websocket.recv())))
        await websocket.wait_closed()

    async with local_push(handler, monkeypatch):
        await autopush.unregister(registration.autopush)
    assert received[0]["uaid"] == "test-uaid"
    assert received[1] == {"messageType": "unregister", "channelID": "test-channel", "code": 200}


@pytest.mark.parametrize("text, expected", [("{}", True), ('{"other":true}', True), ('{"messageType":"hello"}', False), ("[]", False), ("bad JSON", False)])
def test_firefox_pong_detection(text: str, expected: bool) -> None:
    """验证应用 pong 只接受不含 messageType 的 JSON 对象

    :param text: 待识别文本
    :param expected: 协议期望结果
    :return: None, 断言失败表示 pong 误识别
    """
    assert autopush.is_pong(text) is expected
