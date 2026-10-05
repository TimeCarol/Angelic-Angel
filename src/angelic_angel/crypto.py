"""
职责: 处理 Web Push 编码和两种 ECE 密文的解密
导出: encode_base64url, decode_base64url, parse_header_param, decrypt_ece
依赖: cryptography 和 http_ece, 无网络或文件 IO
约束: P-256 原始标量私钥, SEC1 未压缩公钥, UTF-8 由调用方解码
作者: TimeCarol
日期: 2026-10-05 16:25
版本: v1.0
"""

from __future__ import annotations

import base64
import binascii
import struct
from collections.abc import Mapping
from typing import cast

import http_ece
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from angelic_angel.config import AUTH_SECRET_BYTES, P256_PRIVATE_KEY_BYTES, P256_PUBLIC_KEY_BYTES, WebPushKeys
from angelic_angel.errors import DecryptionError

# 旧版 aesgcm 的默认记录大小, 单位为字节, 解密只读
LEGACY_RECORD_SIZE: int = 4096
# RFC 8188 Section 2.1 的 salt, rs 和 idlen 固定头长度, 单位为字节
ECE_FIXED_HEADER_BYTES: int = 21
# RFC 8188 Section 2 的最小记录包含 1 字节分隔符和 16 字节认证标签
ECE_MIN_RECORD_BYTES: int = 17


def encode_base64url(data: bytes) -> str:
    """生成 Web Push 协议使用的无填充 base64url 文本

    :param data: 待编码字节串, 允许空值
    :return: ASCII 字符串, 空输入对应空串
    :副作用: 无, 不修改输入
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_base64url(data: str) -> bytes:
    """严格解码无填充 base64url 文本

    :param data: ASCII base64url 文本, 允许合法的末尾填充
    :return: 解码字节串, 空输入对应空字节串
    :raises DecryptionError: 字符集或填充不合法
    :副作用: 无, 不修改输入
    """
    # RFC 4648 Section 5 使用 - 和 _, 普通 Base64 的 + 和 / 不属于该字母表
    if "+" in data or "/" in data:
        raise DecryptionError("base64url data contains non-URL-safe characters")
    try:
        return base64.b64decode(data + "=" * (-len(data) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as error:
        raise DecryptionError(f"base64 decode failed: {error}") from error


def parse_header_param(header_value: str | None, param_name: str) -> str:
    """提取旧版 Web Push 头的分号分隔参数

    :param header_value: crypto_key 或 encryption 头原文, None 表示缺失
    :param param_name: 所需参数名, 例如 dh 或 salt
    :return: 参数原文, 去除可选双引号
    :raises DecryptionError: 头缺失或参数不存在
    :副作用: 无, 不修改输入
    """
    if header_value is None:
        raise DecryptionError(f"missing required header for param '{param_name}'")
    for part in header_value.split(";"):
        name, separator, value = part.strip().partition("=")
        if separator and name.strip() == param_name:
            return value.strip().strip('"')
    raise DecryptionError(f"param '{param_name}' not found in header")


def decrypt_ece(encrypted: bytes, headers: Mapping[str, str] | None, keys: WebPushKeys) -> bytes:
    """解密 aes128gcm 或旧版 aesgcm 通知

    :param encrypted: ECE 密文字节串, 必须包含该编码要求的记录
    :param headers: AutoPush 通知头, None 或没有 encoding 时采用 aes128gcm
    :param keys: 对应订阅的 P-256 密钥和 16 字节认证随机数
    :return: 完整明文字节串, 不进行 UTF-8 或 JSON 转换
    :raises DecryptionError: 密钥, 编码, 头, 密文认证或记录格式无效
    :副作用: 无, 不修改密钥或密文

    示例::

        plaintext = decrypt_ece(encrypted, {"encoding": "aes128gcm"}, keys)
        text = plaintext.decode("utf-8")
    """
    encoding = (headers or {}).get("encoding", "aes128gcm")
    if encoding not in {"aes128gcm", "aesgcm"}:
        raise DecryptionError(f"unsupported encoding: {encoding}")
    private_key = _load_private_key(keys)
    if encoding == "aes128gcm" and (
        len(encrypted) < ECE_FIXED_HEADER_BYTES
        or len(encrypted) < ECE_FIXED_HEADER_BYTES + encrypted[ECE_FIXED_HEADER_BYTES - 1] + ECE_MIN_RECORD_BYTES
    ):
        # RFC 8188 Section 2 要求至少一条带认证标签的记录, 空内容头不能证明真实性
        raise DecryptionError("aes128gcm content must contain an authenticated record")
    try:
        if encoding == "aesgcm":
            # AutoPush 使用下划线头名, 旧版密文按 4096 字节记录解码
            legacy_headers = headers or {}
            sender_key = decode_base64url(parse_header_param(legacy_headers.get("crypto_key"), "dh"))
            salt = decode_base64url(parse_header_param(legacy_headers.get("encryption"), "salt"))
            return cast(bytes, http_ece.decrypt(
                encrypted, salt=salt, private_key=private_key, dh=sender_key,
                auth_secret=keys.auth_secret, rs=LEGACY_RECORD_SIZE, version="aesgcm",
            ))
        return cast(bytes, http_ece.decrypt(
            encrypted, private_key=private_key, auth_secret=keys.auth_secret, version="aes128gcm",
        ))
    except DecryptionError:
        raise
    except (http_ece.ECEException, ValueError, InvalidTag, IndexError, struct.error) as error:
        # 密文格式或认证失败统一映射到 ACK 101, 不吞掉异常链
        raise DecryptionError(f"{encoding} decryption failed: {error}") from error


def _load_private_key(keys: WebPushKeys) -> ec.EllipticCurvePrivateKey:
    """校验配置密钥并还原 P-256 私钥对象

    :param keys: 接收端的 P-256 密钥及认证随机数
    :return: 对应公钥和私钥一致的 cryptography 对象
    :raises DecryptionError: 长度, 标量或公私钥关系无效
    :副作用: 无, 不修改密钥
    """
    if len(keys.private_key) != P256_PRIVATE_KEY_BYTES or len(keys.public_key) != P256_PUBLIC_KEY_BYTES or len(keys.auth_secret) != AUTH_SECRET_BYTES:
        raise DecryptionError("Web Push keys require 32-byte private, 65-byte public and 16-byte auth values")
    try:
        private_key = ec.derive_private_key(int.from_bytes(keys.private_key, "big"), ec.SECP256R1())
    except ValueError as error:
        raise DecryptionError(f"invalid P-256 private key: {error}") from error
    public_key = private_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    if public_key != keys.public_key:
        raise DecryptionError("configured P-256 public key does not match the private key")
    return private_key
