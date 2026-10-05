"""
职责: 读取和保存凭据及 Web Push 订阅的 TOML 配置
导出: TwitterConfig, WebPushKeys, AutoPushSession, Registration, Config, get_webhook_endpoint
依赖: tomllib, tomli_w, 文件 IO 和 WEBHOOK_ENDPOINT 环境变量
约束: UTF-8 编码, 密钥保存为字节整数数组, 配置实例不支持并发写入
作者: TimeCarol
日期: 2026-10-05 16:23
版本: v1.0
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import tomli_w

from angelic_angel.errors import ConfigError

# P-256 SEC1 未压缩点的长度, 单位为字节, 密钥生成和校验只读
P256_PUBLIC_KEY_BYTES: int = 65
# P-256 私钥标量的长度, 单位为字节, 密钥生成和校验只读
P256_PRIVATE_KEY_BYTES: int = 32
# RFC 8291 Section 3.2 的认证随机数长度, 单位为字节
AUTH_SECRET_BYTES: int = 16


@dataclass(frozen=True)
class TwitterConfig:
    """持有 Twitter/X 会话凭据, 不执行登录或刷新

    调用方持有不可变实例, 字段为 Cookie 原文且不进入 repr

    :param auth_token: 登录 Cookie auth_token, 字符串且不为 None
    :param ct0: 与会话对应的 CSRF Cookie, 字符串且不为 None
    """

    # 初始化时由调用方写入, Twitter 注册读取, 敏感字段禁止出现在 repr
    auth_token: str = field(repr=False)
    # 初始化时由调用方写入, HTTP 请求同时用于 CSRF 头和 Cookie
    ct0: str = field(repr=False)


@dataclass(frozen=True)
class WebPushKeys:
    """持有 Web Push 密钥材料, 不承担密钥生成和解密

    调用方持有不可变字节串, 有效密钥长度依次为 65, 32, 16 字节

    :param public_key: SEC1 未压缩格式的 P-256 公钥, 单位为字节
    :param private_key: P-256 原始私钥标量, 单位为字节
    :param auth_secret: Web Push 认证随机数, 单位为字节
    """

    # 生成时写入, 注册接口及解密读取, 使用 bytes 保证材料不可变
    public_key: bytes
    # 生成时写入, 仅解密读取, repr 不暴露私钥
    private_key: bytes = field(repr=False)
    # 生成时写入, 注册及解密读取, repr 不暴露认证随机数
    auth_secret: bytes = field(repr=False)


@dataclass(frozen=True)
class AutoPushSession:
    """标识 AutoPush 用户和通道, 不持有 WebSocket 连接

    实例不可变, 注册流程创建, listener 在恢复订阅时整体替换

    :param uaid: AutoPush hello 返回的用户标识, 字符串
    :param channel_id: AutoPush register 使用的 UUID 字符串
    """

    # 服务端分配, hello 重连读取, 无缺省值以避免静默创建新订阅
    uaid: str
    # 注册时生成, unregister 和 ACK 读取, 整体替换而非原地修改
    channel_id: str


@dataclass(frozen=True)
class Registration:
    """组合完整的推送订阅, 不负责注册或网络资源释放

    实例不可变, endpoint, 会话和密钥必须属于同一次订阅

    :param endpoint: AutoPush 分配的推送地址
    :param autopush: 对应 endpoint 的用户及通道
    :param keys: 与 Twitter/X 注册一致的接收端密钥
    """

    # 注册时写入, Twitter/X API 读取, 不从本地地址推导
    endpoint: str
    # 注册时写入, 监听和注销读取, 与 endpoint 共同替换
    autopush: AutoPushSession
    # 注册时写入, 通知解密读取, UAID 失效后必须重新生成
    keys: WebPushKeys


@dataclass
class Config:
    """管理配置文件的内存表示, 不持有长期文件句柄

    命令处理方持有可变实例, 仅 registration 由注册和注销流程替换
    不支持多线程同时修改或保存同一配置

    :param twitter: Twitter/X 凭据, 不为 None
    :param registration: 已注册订阅, None 表示尚未注册
    """

    # 初始化或读取文件时写入, 注册流程只读, 无默认凭据
    twitter: TwitterConfig
    # 注册或注销时替换, 默认 None 对应仅执行 init 的状态
    registration: Registration | None = None

    @classmethod
    def load(cls, path: Path) -> Config:
        """读取并校验 TOML 配置文件

        :param path: UTF-8 TOML 文件路径, 不为 None
        :return: 新建配置实例, 缺少 registration 时对应未注册
        :raises ConfigError: 文件不可读, TOML 无效或字段类型不合法
        :副作用: 读取文件, 不修改文件或环境变量
        """
        try:
            document: dict[str, object] = tomllib.loads(path.read_text(encoding="utf-8"))
            twitter = _table(document.get("twitter"), "twitter")
            config = cls(TwitterConfig(_text(twitter, "auth_token"), _text(twitter, "ct0")))
            if "registration" in document:
                config.registration = _registration_from_document(document["registration"])
            return config
        except (OSError, UnicodeError, ValueError, ConfigError) as error:
            # 配置错误必须携带路径, 以便区分多个配置文件的故障
            raise ConfigError(f"failed to load config ({path}): {error}") from error

    def save(self, path: Path) -> None:
        """保存凭据和完整订阅至 TOML 文件

        :param path: 目标文件路径, 父目录必须已经存在
        :return: None 表示文件写入完成
        :raises ConfigError: 配置无法序列化或文件无法写入
        :副作用: 覆盖目标文件, 不创建父目录
        """
        document: dict[str, object] = {
            "twitter": {"auth_token": self.twitter.auth_token, "ct0": self.twitter.ct0}
        }
        if self.registration is not None:
            registration = self.registration
            document["registration"] = {
                "endpoint": registration.endpoint,
                "autopush": {
                    "uaid": registration.autopush.uaid,
                    "channel_id": registration.autopush.channel_id,
                },
                "keys": {
                    "public_key": list(registration.keys.public_key),
                    "private_key": list(registration.keys.private_key),
                    "auth_secret": list(registration.keys.auth_secret),
                },
            }
        try:
            path.write_text(tomli_w.dumps(document), encoding="utf-8")
        except (OSError, ValueError, TypeError) as error:
            raise ConfigError(f"failed to save config ({path}): {error}") from error


def get_webhook_endpoint() -> str:
    """取得通知转发地址

    :return: WEBHOOK_ENDPOINT 原始字符串, 不为 None
    :raises ConfigError: 未设置 WEBHOOK_ENDPOINT
    :副作用: 读取环境变量, 地址合法性由 HTTP 客户端校验
    """
    endpoint = os.environ.get("WEBHOOK_ENDPOINT")
    if endpoint is None:
        raise ConfigError("WEBHOOK_ENDPOINT environment variable is not set")
    return endpoint


def _table(value: object, name: str) -> dict[str, object]:
    """校验 TOML 表, 不修改输入

    :param value: TOML 解析后的字段, 允许 None 以报告缺失
    :param name: 用于定位错误的表名
    :return: 原始字典
    :raises ConfigError: 字段不是表
    """
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be a TOML table")
    return cast(dict[str, object], value)


def _text(table: dict[str, object], name: str) -> str:
    """读取字符串字段, 不修改输入

    :param table: 待读取的 TOML 表
    :param name: 必须存在的字段名
    :return: 字符串原文, 空串保留以便由实际使用方判断有效性
    :raises ConfigError: 字段缺失或不是字符串
    """
    value = table.get(name)
    if not isinstance(value, str):
        raise ConfigError(f"{name} must be a string")
    return value


def _key_bytes(table: dict[str, object], name: str) -> bytes:
    """读取 TOML 整数形式的字节数组, 不修改输入

    :param table: 密钥 TOML 表
    :param name: 密钥字段名
    :return: 不可变字节串, 长度在解密时校验
    :raises ConfigError: 字段不是 0 至 255 的整数数组
    """
    values = table.get(name)
    if not isinstance(values, list) or any(type(value) is not int or not 0 <= value <= 255 for value in values):
        raise ConfigError(f"{name} must be an array of byte integers (0..255)")
    return bytes(values)


def _registration_from_document(value: object) -> Registration:
    """组装订阅字段, 不访问网络或修改输入

    :param value: registration TOML 表
    :return: 完整不可变订阅
    :raises ConfigError: 任一必需字段缺失或类型错误
    """
    registration = _table(value, "registration")
    autopush = _table(registration.get("autopush"), "registration.autopush")
    keys = _table(registration.get("keys"), "registration.keys")
    return Registration(
        endpoint=_text(registration, "endpoint"),
        autopush=AutoPushSession(_text(autopush, "uaid"), _text(autopush, "channel_id")),
        keys=WebPushKeys(_key_bytes(keys, "public_key"), _key_bytes(keys, "private_key"), _key_bytes(keys, "auth_secret")),
    )
