"""
职责: 实现 Mozilla AutoPush 的订阅, 重连, 通知和 ACK 协议
导出: AckCode, Notification, AutoPushClient, connect_ws, register_new, connect_and_listen, unregister, is_pong
依赖: asyncio, websockets, TCP keepalive 和远端网络
约束: 一个客户端仅供单个事件循环顺序使用, 连接由创建方或 listener 关闭
作者: TimeCarol
日期: 2026-10-05 16:29
版本: v1.0
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import uuid
from collections import deque
from dataclasses import dataclass
from enum import IntEnum
from http import HTTPStatus
from typing import cast

from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed, WebSocketException
from websockets.typing import Origin

from angelic_angel.config import AutoPushSession, Registration, WebPushKeys
from angelic_angel.crypto import encode_base64url
from angelic_angel.errors import AutoPushError, ServerBackoffError

# Mozilla AutoPush 生产端点, 注册和监听只读
AUTOPUSH_WS_URL: str = "wss://push.services.mozilla.com/"
# Twitter/X applicationServerKey, 注册只读, 单位为字节
TWITTER_VAPID_PUBLIC_KEY: bytes = bytes([
    4, 94, 104, 18, 141, 49, 13, 74, 96, 202, 82, 131, 78, 91, 29, 242, 150, 102, 197, 0, 53, 149,
    230, 8, 54, 38, 62, 173, 43, 28, 89, 130, 191, 222, 213, 128, 147, 62, 21, 49, 187, 95, 212,
    194, 196, 253, 140, 157, 234, 34, 8, 234, 143, 158, 221, 15, 83, 8, 222, 111, 100, 204, 213, 48, 75,
])
# Firefox 握手标识, connect_ws 只读
USER_AGENT: str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:134.0) Gecko/20100101 Firefox/134.0"
# 应用心跳间隔为 5 分钟, 单位为秒, 客户端只读
PING_INTERVAL_SECS: float = 300.0
# Firefox requestTimeout 对应的握手和应用 pong 超时, 单位为秒
PONG_TIMEOUT_SECS: float = 10.0
# RFC 6455 Ping 间隔, 单位为秒, websockets 负责控制帧
WS_PING_INTERVAL_SECS: float = 150.0
# TCP 空闲探测时间, 单位为秒, 用于避免 NAT/LB 删除空闲连接
TCP_KEEPALIVE_SECS: int = 60
# Firefox kBACKOFF_WS_STATUS_CODE, listener 根据此值执行服务器退避
BACKOFF_WS_STATUS_CODE: int = 4774
# 每个连接记忆的通知版本数量, 用于有限内存去重
MAX_RECENT_MESSAGE_IDS: int = 100
# 模块日志由 CLI 配置级别, 协议层只写日志
logger: logging.Logger = logging.getLogger(__name__)


class AckCode(IntEnum):
    """描述 Firefox 兼容的通知处理结果, 不负责发送 ACK

    枚举成员不可变, 协议线上的整数始终为 100, 101 或 102
    """

    # Firefox ACK 协议: 已处理或空通知, 通知循环读取
    DELIVERED = 100
    # Firefox ACK 协议: base64, ECE 或 UTF-8 解密失败
    DECRYPTION_ERROR = 101
    # Firefox ACK 协议: 解密之外的处理或传输失败
    NOT_DELIVERED = 102


@dataclass(frozen=True)
class Notification:
    """表示一个 AutoPush 通知, 不执行解密或转发

    实例由客户端创建并由处理循环持有, 字段不可重新赋值
    headers 仅供读取, 同一通知版本在连接内最多交付一次

    :param channel_id: 通知所属的通道标识
    :param version: 服务端通知版本, 用于 ACK 和去重
    :param data: base64url 密文, None 表示空通知
    :param headers: AutoPush 编码头, None 表示使用缺省编码
    """

    # 协议解析时写入, ACK 读取, 不推导成当前连接的通道
    channel_id: str
    # 协议解析时写入, 去重及 ACK 读取, 保存服务端原文
    version: str
    # 协议解析时写入, 解密读取, None 对应不带 payload 的通知
    data: str | None = None
    # 协议解析时写入, 解密读取, 无头时按 aes128gcm 处理
    headers: dict[str, str] | None = None


class AutoPushClient:
    """管理一个已握手连接的通知和去重状态, 不负责重连策略

    创建方持有客户端并调用 close, 内部状态由通知读取方法修改
    不支持并发调用 next_notification, 最近版本队列和集合始终保持一致

    :param websocket: 已完成 hello 的 WebSocket 连接
    :param session: 与该连接对应的用户和通道
    """

    def __init__(self, websocket: ClientConnection, session: AutoPushSession) -> None:
        """接管连接并初始化当前连接的去重状态

        :param websocket: 已握手且尚未关闭的连接
        :param session: 已注册的会话, 不为 None
        :return: None, 创建后调用方必须最终关闭客户端
        :副作用: 接管连接生命周期, 不发网络请求
        """
        # 当前客户端拥有连接, 仅顺序发送和读取, close 负责释放
        self._websocket: ClientConnection = websocket
        # 不可变会话由创建方写入, 标识属性只读
        self._session: AutoPushSession = session
        # 读通知时更新的插入顺序队列, 默认空以便连接内独立去重
        self._recent_versions: deque[str] = deque()
        # 与队列同步更新的查找集合, 默认空, 不跨连接持久化
        self._recent_version_set: set[str] = set()

    @property
    def uaid(self) -> str:
        """读取当前连接的用户标识

        :return: hello 已确认的 UAID, 无副作用
        """
        return self._session.uaid

    @property
    def channel_id(self) -> str:
        """读取当前连接的通道标识

        :return: 配置中注册的 channel_id, 无副作用
        """
        return self._session.channel_id

    async def close(self) -> None:
        """释放客户端持有的连接

        :return: None 表示关闭握手完成, 重复调用安全
        :副作用: 发送 WebSocket 关闭帧并释放底层网络连接
        """
        await self._websocket.close()

    async def next_notification(self) -> Notification | None:
        """等待下一条未重复的通知并维护应用心跳

        :return: 通知实例, None 表示服务端关闭连接
        :raises AutoPushError: 网络, JSON 协议或应用 pong 超时
        :raises ServerBackoffError: 服务端通过 4774 请求延迟重连
        :副作用: 读取连接, 发心跳, 更新去重状态并确认重复通知
        """
        loop = asyncio.get_running_loop()
        ping_deadline = loop.time() + PING_INTERVAL_SECS
        pong_deadline: float | None = None
        while True:
            deadline = pong_deadline if pong_deadline is not None else ping_deadline
            try:
                message = await _receive(self._websocket, max(0.0, deadline - loop.time()))
            except TimeoutError as error:
                if pong_deadline is not None:
                    raise AutoPushError("pong timed out, reconnection needed") from error
                await _send(self._websocket, {})
                pong_deadline = loop.time() + PONG_TIMEOUT_SECS
                continue
            if message is None:
                return None
            if "messageType" not in message:
                pong_deadline = None
                ping_deadline = loop.time() + PING_INTERVAL_SECS
                continue
            if message.get("messageType") != "notification":
                # 非通知响应不算应用 pong, 保留当前 pong 的绝对超时
                if pong_deadline is None:
                    ping_deadline = loop.time() + PING_INTERVAL_SECS
                continue
            pong_deadline = None
            ping_deadline = loop.time() + PING_INTERVAL_SECS
            notification = _parse_notification(message)
            if await self._is_duplicate(notification):
                continue
            return notification

    async def ack_notification(self, channel_id: str, version: str, code: AckCode) -> None:
        """发送通知处理结果

        :param channel_id: 收到通知的通道标识
        :param version: 收到通知的服务端版本
        :param code: Firefox 兼容的 ACK 100, 101 或 102
        :return: None 表示 ACK 已写入连接
        :raises AutoPushError: 连接关闭或发送失败
        :副作用: 向 AutoPush 发送 ACK, 不修改去重状态
        """
        await _send(self._websocket, {
            "messageType": "ack",
            "updates": [{"channelID": channel_id, "version": version, "code": int(code)}],
        })

    async def _is_duplicate(self, notification: Notification) -> bool:
        """识别重复版本并维护有界缓存

        :param notification: 已解析的通知
        :return: True 表示重复且已发送 ACK 100, False 表示首次交付
        :raises AutoPushError: 重复通知的 ACK 发送失败
        :副作用: 修改最近版本队列和集合, 可能发送 ACK
        """
        if notification.version in self._recent_version_set:
            # 仍确认重复消息, 避免服务端持续重试
            await self.ack_notification(notification.channel_id, notification.version, AckCode.DELIVERED)
            return True
        if len(self._recent_versions) >= MAX_RECENT_MESSAGE_IDS:
            self._recent_version_set.remove(self._recent_versions.popleft())
        self._recent_versions.append(notification.version)
        self._recent_version_set.add(notification.version)
        return False


async def connect_ws(url: str) -> ClientConnection:
    """建立具有 Firefox 头和 TCP keepalive 的连接

    :param url: ws 或 wss URL, 生产使用 Mozilla AutoPush 地址
    :return: 已连接的 WebSocket, 调用方负责关闭
    :raises AutoPushError: 握手, 网络或 keepalive 设置失败
    :副作用: 创建 TCP/TLS 连接, 设置 60 秒 keepalive 和 150 秒 Ping
    """
    websocket: ClientConnection | None = None
    try:
        websocket = await connect(
            url, origin=Origin("https://x.com"), user_agent_header=USER_AGENT, proxy=None,
            ping_interval=WS_PING_INTERVAL_SECS, ping_timeout=None, compression=None,
            open_timeout=PONG_TIMEOUT_SECS, close_timeout=PONG_TIMEOUT_SECS,
        )
        tcp_socket = websocket.transport.get_extra_info("socket")
        tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        tcp_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        keepalive_option = getattr(socket, "TCP_KEEPIDLE", getattr(socket, "TCP_KEEPALIVE", None))
        if keepalive_option is not None:
            tcp_socket.setsockopt(socket.IPPROTO_TCP, keepalive_option, TCP_KEEPALIVE_SECS)
        elif hasattr(socket, "SIO_KEEPALIVE_VALS"):
            # Windows 的 keepalive 设置使用毫秒, 需要显式转换单位
            tcp_socket.ioctl(socket.SIO_KEEPALIVE_VALS, (1, TCP_KEEPALIVE_SECS * 1000, TCP_KEEPALIVE_SECS * 1000))
        return websocket
    except (OSError, TimeoutError, WebSocketException) as error:
        if websocket is not None:
            await websocket.close()
        raise AutoPushError(f"WebSocket connect failed ({url}): {error}") from error


async def register_new(keys: WebPushKeys) -> Registration:
    """向 AutoPush 注册新的用户和通道

    :param keys: 新生成的 Web Push 接收密钥, 不为 None
    :return: 含 endpoint, 会话和原始 keys 的完整订阅
    :raises AutoPushError: hello/register 被拒绝, 响应无效或超时
    :副作用: 创建远端订阅, 返回或失败时均关闭注册连接
    """
    websocket = await connect_ws(AUTOPUSH_WS_URL)
    try:
        uaid = await _hello(websocket, "")
        channel_id = str(uuid.uuid4())
        await _send(websocket, {
            "messageType": "register", "channelID": channel_id,
            "key": encode_base64url(TWITTER_VAPID_PUBLIC_KEY),
        })
        response = await _response(websocket, "register")
        return Registration(_required_text(response, "pushEndpoint"), AutoPushSession(uaid, channel_id), keys)
    finally:
        await websocket.close()


async def connect_and_listen(session: AutoPushSession, keys: WebPushKeys) -> AutoPushClient | Registration:
    """恢复现有连接或返回 UAID 失效后的新订阅

    :param session: 保存的 AutoPush 用户和通道
    :param keys: 保存的接收密钥, 失效时不复用
    :return: 已连接客户端, 或需要同步至 Twitter/X 并持久化的新订阅
    :raises AutoPushError: hello, 网络或新订阅注册失败
    :副作用: 创建连接, UAID 变化时关闭旧连接并生成新密钥及通道
    """
    from angelic_angel.push import generate_keys

    websocket = await connect_ws(AUTOPUSH_WS_URL)
    try:
        uaid = await _hello(websocket, session.uaid)
    except BaseException:
        # 包括任务取消在内的握手失败均释放连接, 异常原样向上传播
        await websocket.close()
        raise
    if uaid == session.uaid:
        return AutoPushClient(websocket, session)
    await websocket.close()
    logger.warning("UAID invalidated, creating a new push subscription")
    return await register_new(generate_keys())


async def unregister(session: AutoPushSession) -> None:
    """从 AutoPush 删除保存的订阅通道

    :param session: 保存的用户和通道标识
    :return: None 表示注销请求已发送, 不等待注销响应
    :raises AutoPushError: hello 失败, 请求无法发送或网络超时
    :副作用: 删除远端通道, 始终关闭临时连接, 不修改本地配置
    """
    websocket = await connect_ws(AUTOPUSH_WS_URL)
    try:
        await _hello(websocket, session.uaid)
        await _send(websocket, {"messageType": "unregister", "channelID": session.channel_id, "code": 200})
    finally:
        await websocket.close()


def is_pong(text: str) -> bool:
    """识别 Firefox 兼容的应用层 pong 文本

    :param text: 服务端文本帧原文
    :return: True 表示 JSON 对象不含 messageType, 无效 JSON 返回 False
    :副作用: 无, 不修改输入或发送响应
    """
    try:
        value: object = json.loads(text)
    except ValueError:
        return False
    return isinstance(value, dict) and "messageType" not in value


async def _send(websocket: ClientConnection, message: dict[str, object]) -> None:
    """发送协议 JSON 并统一网络错误

    :param websocket: 已连接 WebSocket
    :param message: 可序列化的协议对象
    :return: None 表示发送完成
    :raises AutoPushError: WebSocket 写入失败
    :副作用: 写入网络连接
    """
    try:
        await websocket.send(json.dumps(message, ensure_ascii=False))
    except (OSError, WebSocketException) as error:
        raise AutoPushError(f"AutoPush send failed: {error}") from error


async def _receive(websocket: ClientConnection, timeout: float) -> dict[str, object] | None:
    """在限定时间内取得下一条 JSON 协议响应

    :param websocket: 已连接 WebSocket
    :param timeout: 剩余等待秒数, 非负
    :return: JSON 对象, None 表示连接关闭, 二进制帧作为无关消息忽略
    :raises TimeoutError: 时间耗尽
    :raises AutoPushError: JSON 格式错误或网络失败
    :raises ServerBackoffError: 收到关闭码 4774
    :副作用: 读取网络, 控制帧由 websockets 自动响应
    """
    try:
        raw = await asyncio.wait_for(websocket.recv(), timeout)
    except ConnectionClosed as error:
        if error.rcvd is not None and error.rcvd.code == BACKOFF_WS_STATUS_CODE:
            raise ServerBackoffError("BACKOFF: server requested backoff") from error
        if error.rcvd is not None:
            return None
        raise AutoPushError(f"AutoPush connection lost: {error}") from error
    except TimeoutError:
        # Python 的 TimeoutError 也是 OSError, 心跳调度必须单独收到超时信号
        raise
    except (OSError, WebSocketException) as error:
        raise AutoPushError(f"AutoPush receive failed: {error}") from error
    if isinstance(raw, bytes):
        return {"messageType": "binary"}
    try:
        value: object = json.loads(raw)
    except ValueError as error:
        raise AutoPushError(f"invalid AutoPush JSON: {error}") from error
    if not isinstance(value, dict):
        raise AutoPushError("AutoPush response must be a JSON object")
    return cast(dict[str, object], value)


async def _response(websocket: ClientConnection, expected_type: str) -> dict[str, object]:
    """取得并校验注册阶段的单个响应

    :param websocket: 已连接 WebSocket
    :param expected_type: hello 或 register
    :return: 状态 200 且类型匹配的响应
    :raises AutoPushError: 连接关闭, 超时, 类型错误或状态非 200
    :副作用: 读取一次协议响应
    """
    try:
        response = await _receive(websocket, PONG_TIMEOUT_SECS)
    except TimeoutError as error:
        raise AutoPushError(f"{expected_type} response timed out ({PONG_TIMEOUT_SECS:g}s)") from error
    if response is None or response.get("messageType") != expected_type:
        raise AutoPushError(f"unexpected response: expected {expected_type}")
    if response.get("status") != HTTPStatus.OK:
        raise AutoPushError(f"{expected_type} failed: status={response.get('status')}")
    return response


async def _hello(websocket: ClientConnection, uaid: str) -> str:
    """按 Firefox 兼容格式完成 hello

    :param websocket: 新建连接
    :param uaid: 保存的 UAID, 空串表示注册新用户
    :return: 服务端确认或新分配的 UAID
    :raises AutoPushError: hello 被拒绝, 格式错误或超时
    :副作用: 发送 hello 并读取响应, 不发送 channelIDs
    """
    await _send(websocket, {"messageType": "hello", "uaid": uaid, "use_webpush": True, "broadcasts": {}})
    return _required_text(await _response(websocket, "hello"), "uaid")


def _required_text(message: dict[str, object], field_name: str) -> str:
    """校验协议必需的字符串字段

    :param message: 解析后的协议对象
    :param field_name: 字段名
    :return: 字符串原文
    :raises AutoPushError: 字段缺失或不是字符串
    :副作用: 无, 不修改输入
    """
    value = message.get(field_name)
    if not isinstance(value, str):
        raise AutoPushError(f"AutoPush field '{field_name}' must be a string")
    return value


def _parse_notification(message: dict[str, object]) -> Notification:
    """校验并构造通知对象

    :param message: messageType 为 notification 的 JSON 对象
    :return: 可进行解密和 ACK 的通知
    :raises AutoPushError: 通道, 版本, 密文或头的类型不合法
    :副作用: 无, 不修改输入
    """
    data = message.get("data")
    headers = message.get("headers")
    if data is not None and not isinstance(data, str):
        raise AutoPushError("notification data must be a string or null")
    if headers is not None and (
        not isinstance(headers, dict)
        or any(not isinstance(key, str) or not isinstance(value, str) for key, value in headers.items())
    ):
        raise AutoPushError("notification headers must contain string values")
    return Notification(
        _required_text(message, "channelID"), _required_text(message, "version"),
        data, cast(dict[str, str] | None, headers),
    )
