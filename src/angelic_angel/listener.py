"""
职责: 解密转发通知并按 Firefox 兼容策略恢复监听连接
导出: listen, calc_backoff, run_notification_loop, handle_notification_data, send_to_webhook
依赖: AutoPush 和 Twitter/X 网络, ECE 解密, HTTP webhook, 配置文件 IO
约束: 单事件循环顺序交付, UAID 失效后先同步 Twitter/X 再持久化新订阅
作者: TimeCarol
日期: 2026-10-05 16:34
版本: v1.0
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import httpx

from angelic_angel import autopush, twitter
from angelic_angel.autopush import AckCode, AutoPushClient
from angelic_angel.config import Config, Registration, WebPushKeys, get_webhook_endpoint
from angelic_angel.crypto import decode_base64url, decrypt_ece
from angelic_angel.errors import (
    AngelicAngelError,
    DecryptionError,
    HTTPError,
    ReregistrationError,
    ServerBackoffError,
)

# 首次握手失败等待 5 秒, 单位为秒, 重连策略只读
RETRY_BASE_INTERVAL_SECS: int = 5
# 指数退避上限, 单位为秒, 与应用心跳间隔一致
MAX_RETRY_INTERVAL_SECS: int = 300
# 5 * 2^6 已超过 300 秒上限, 更大指数无需计算
MAX_BACKOFF_EXPONENT: int = 6
# 已连接会话关闭后的等待, 单位为秒
RECONNECT_INTERVAL_SECS: int = 1
# Firefox 关闭码 4774 对应的强制退避, 单位为秒
SERVER_BACKOFF_SECS: int = 1800
# 模块日志由 CLI 配置, 不输出凭据或解密后的通知内容
logger: logging.Logger = logging.getLogger(__name__)


class SessionState(Enum):
    """区分会话在握手前后的退出原因, 不执行恢复操作

    成员不可变, 成功握手后的关闭必须重置重试计数
    """

    # 已连接后正常关闭, 对应 1 秒重连
    NORMAL_CLOSE = "normal_close"
    # 已连接后网络失败, 对应 1 秒重连并重置计数
    DISCONNECTED = "disconnected"
    # hello 之前失败, 对应指数退避
    CONNECTION_FAILED = "connection_failed"
    # UAID 恢复无法完成, 对应终止监听
    FATAL = "fatal"


@dataclass(frozen=True)
class SessionOutcome:
    """保留会话结果和可能更新的订阅, 不持有活动连接

    内部不可变实例由一次监听创建, 正常关闭时 error 必须为 None

    :param state: 会话退出阶段
    :param registration: 本轮最终有效的订阅
    :param error: 失败原因, 正常关闭为 None
    """

    # 单会话函数写入, 重连循环读取, 无默认退出状态
    state: SessionState
    # 会话恢复时替换, 下一次监听读取, 避免继续使用旧密钥
    registration: Registration
    # 正常关闭默认 None, 失败时由会话函数写入原始应用异常
    error: AngelicAngelError | None = None


def calc_backoff(retry_count: int) -> int:
    """计算有上限的指数退避

    :param retry_count: 连续握手失败次数, 非负整数, 0 和 1 均对应首次等待
    :return: 秒数, 序列为 5, 10, 20, 40, 80, 160, 300 并封顶
    :副作用: 无, 大计数不会构造巨大整数
    """
    # 到达上限后无需再增长指数, 避免持续失败时构造巨大整数
    return min(RETRY_BASE_INTERVAL_SECS * (1 << min(max(retry_count - 1, 0), MAX_BACKOFF_EXPONENT)), MAX_RETRY_INTERVAL_SECS)


async def listen(registration: Registration, config_path: Path) -> None:
    """持续监听通知并自动重连

    :param registration: 已完成 Twitter/X 注册的订阅
    :param config_path: 对应配置文件路径, UAID 更新时需可读写
    :return: 正常持续运行, 任务取消时向调用方传播取消
    :raises ReregistrationError: UAID 恢复无法完成或恢复后仍失效
    :副作用: 建立网络连接, 转发 webhook, 必要时更新 Twitter/X 及配置
    """
    retry_count = 0
    while True:
        outcome = await _listen_once(registration, config_path)
        registration = outcome.registration
        if outcome.state is SessionState.FATAL:
            assert outcome.error is not None
            raise outcome.error
        if outcome.state is not SessionState.CONNECTION_FAILED:
            retry_count = 0
        if isinstance(outcome.error, ServerBackoffError):
            # Firefox 服务端退避优先于普通网络重试, 包括 hello 阶段关闭
            delay = SERVER_BACKOFF_SECS
            logger.warning("server requested backoff, reconnecting in %s seconds", delay)
        elif outcome.state is SessionState.CONNECTION_FAILED:
            retry_count += 1
            delay = calc_backoff(retry_count)
            logger.warning("connection failed, retry %s in %ss: %s", retry_count, delay, outcome.error)
        else:
            delay = RECONNECT_INTERVAL_SECS
            logger.info("connected session ended, reconnecting in %ss", delay)
        await asyncio.sleep(delay)


async def _listen_once(registration: Registration, config_path: Path) -> SessionOutcome:
    """执行单次会话并区分握手前后的失败

    :param registration: 当前订阅
    :param config_path: 恢复后保存配置的路径
    :return: 退出阶段, 最终订阅和可选错误
    :副作用: 持有一次连接, 退出时关闭, 任务取消不被吞掉
    """
    try:
        client, registration = await _try_connect(registration, config_path)
    except ReregistrationError as error:
        return SessionOutcome(SessionState.FATAL, registration, error)
    except AngelicAngelError as error:
        return SessionOutcome(SessionState.CONNECTION_FAILED, registration, error)
    try:
        await run_notification_loop(client, registration)
        return SessionOutcome(SessionState.NORMAL_CLOSE, registration)
    except AngelicAngelError as error:
        return SessionOutcome(SessionState.DISCONNECTED, registration, error)
    finally:
        await client.close()


async def _try_connect(registration: Registration, config_path: Path) -> tuple[AutoPushClient, Registration]:
    """建立连接并完整恢复失效的 UAID 订阅

    :param registration: 保存的订阅
    :param config_path: 对应配置路径
    :return: 调用方负责关闭的客户端和最终有效的订阅
    :raises AngelicAngelError: 首次连接失败
    :raises ReregistrationError: 更新 Twitter/X, 保存配置或二次连接失败
    :副作用: 可能重注册 Twitter/X 并覆盖配置, 未完成恢复时不交付客户端
    """
    result = await autopush.connect_and_listen(registration.autopush, registration.keys)
    if isinstance(result, AutoPushClient):
        return result, registration
    try:
        full_config = Config.load(config_path)
        await twitter.register(full_config.twitter, result)
        full_config.registration = result
        full_config.save(config_path)
        connected = await autopush.connect_and_listen(result.autopush, result.keys)
        if isinstance(connected, Registration):
            raise ReregistrationError("still failed after re-registration")
        return connected, result
    except AngelicAngelError as error:
        raise ReregistrationError(f"UAID invalid, subscription recovery failed: {error}") from error


async def run_notification_loop(client: AutoPushClient, registration: Registration) -> None:
    """顺序处理通知并为每条通知发送对应的 ACK

    :param client: 已完成 hello 的客户端, 由调用方负责关闭
    :param registration: 当前连接对应的密钥和订阅
    :return: None 表示远端正常关闭
    :raises AutoPushError: 接收或 ACK 失败
    :副作用: 解密, 发 HTTP webhook 和 ACK, webhook 跳过 SSL 证书校验
    """
    # webhook 按用户约定跳过 SSL 证书校验, 允许使用自签名 HTTPS 证书
    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=None) as http_client:
        while (notification := await client.next_notification()) is not None:
            ack_code = AckCode.DELIVERED
            if notification.data is not None:
                ack_code = await _process_data(notification.data, notification.headers, registration.keys, http_client)
            await client.ack_notification(notification.channel_id, notification.version, ack_code)


async def _process_data(data: str, headers: Mapping[str, str] | None, keys: WebPushKeys, client: httpx.AsyncClient) -> AckCode:
    """将单条消息处理结果映射成协议 ACK

    :param data: base64url 密文
    :param headers: 可选编码头
    :param keys: 接收端密钥
    :param client: 本会话共用的 HTTP 客户端
    :return: 成功为 100, 解密失败为 101, 其他应用失败为 102
    :副作用: 转发 webhook, 捕获可预期单条错误并记录原因
    """
    try:
        await handle_notification_data(data, headers, keys, client)
        return AckCode.DELIVERED
    except DecryptionError as error:
        logger.warning("notification decryption failed: %s", error)
        return AckCode.DECRYPTION_ERROR
    except AngelicAngelError as error:
        logger.warning("notification delivery failed: %s", error)
        return AckCode.NOT_DELIVERED


async def handle_notification_data(data: str, headers: Mapping[str, str] | None, keys: WebPushKeys, client: httpx.AsyncClient) -> None:
    """解密通知并转发 JSON 或原文包装

    :param data: 通知的 base64url 密文
    :param headers: AutoPush 编码头, None 表示 aes128gcm
    :param keys: 对应订阅的接收密钥
    :param client: 调用方持有且尚未关闭的 HTTP 客户端
    :return: None 表示解密及 webhook 请求完成
    :raises DecryptionError: base64, ECE 或 UTF-8 无效
    :raises AngelicAngelError: webhook 配置或传输失败
    :副作用: 向配置的 webhook 发请求, 不输出解密内容
    """
    decrypted = decrypt_ece(decode_base64url(data), headers, keys)
    try:
        text = decrypted.decode("utf-8")
    except UnicodeError as error:
        raise DecryptionError(f"UTF-8 conversion failed: {error}") from error
    try:
        payload: object = json.loads(text)
    except ValueError:
        # 非 JSON 文本仍可用于 webhook, 保留原文而不将其视为解密失败
        payload = {"raw": text}
    await send_to_webhook(payload, client)


async def send_to_webhook(payload: object, client: httpx.AsyncClient) -> None:
    """将通知 JSON 发送到 WEBHOOK_ENDPOINT

    :param payload: 任意 JSON 值, 非 JSON 文本由调用方包装为 raw 字段
    :param client: 当前监听会话共用且关闭 SSL 证书校验的 HTTP 客户端
    :return: None 表示收到 HTTP 响应, 非 2xx 仅记录警告
    :raises ConfigError: 未设置 WEBHOOK_ENDPOINT
    :raises HTTPError: 请求无法发送或地址无效
    :副作用: 发 HTTP POST, 不改变环境变量或关闭调用方客户端
    """
    endpoint = get_webhook_endpoint()
    try:
        response = await client.post(endpoint, json=payload)
    except (httpx.HTTPError, httpx.InvalidURL, ValueError) as error:
        raise HTTPError(f"webhook request failed ({endpoint}): {error}") from error
    if not response.is_success:
        # HTTP 非 2xx 仅记录状态, 调用方仍发送 ACK 100
        logger.warning("webhook returned HTTP %s", response.status_code)
