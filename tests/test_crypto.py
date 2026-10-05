"""
职责: 验证标准密文, 两种编码和密钥错误的解密行为
导出: pytest 测试函数
依赖: RFC 8291 固定样例, 独立加密辅助函数, 无 IO
约束: 使用标准公开测试密钥, 不读取真实配置
作者: TimeCarol
日期: 2026-10-05 16:42
版本: v1.0
"""

from __future__ import annotations

from dataclasses import replace
from typing import Literal

import pytest

from angelic_angel.config import Registration, WebPushKeys
from angelic_angel.crypto import decode_base64url, decrypt_ece, parse_header_param
from angelic_angel.errors import DecryptionError
from angelic_angel.push import generate_keys
from tests.helpers import encrypt_notification


def test_rfc8291_standard_ciphertext() -> None:
    """验证 RFC 8291 Section 5 的公开密文可解密

    :return: None, 断言失败表示与协议固定样例不兼容
    """
    # RFC 8291 Section 5 的接收端密钥及认证随机数, 不依赖本地加密实现
    keys = WebPushKeys(
        decode_base64url("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"),
        decode_base64url("q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"),
        decode_base64url("BTBZMqHH6r4Tts7J_aSIgg"),
    )
    encrypted = decode_base64url(
        "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml"
        "mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT"
        "pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
    )
    assert decrypt_ece(encrypted, None, keys) == b"When I grow up, I want to be a watermelon"


@pytest.mark.parametrize("encoding", ["aes128gcm", "aesgcm"])
def test_independent_encryption_preserves_unicode(registration: Registration, encoding: Literal["aes128gcm", "aesgcm"]) -> None:
    """验证两种独立加密格式都能还原中文和 emoji

    :param registration: 测试密钥
    :param encoding: 要验证的编码格式
    :return: None, 断言失败表示编码或 ECDH 上下文错误
    """
    plaintext = '{"text":"推送通知 🌸"}'.encode()
    data, headers = encrypt_notification(plaintext, registration.keys, encoding)
    assert decrypt_ece(decode_base64url(data), headers, registration.keys) == plaintext


def test_each_subscription_has_fresh_key_material() -> None:
    """验证每次密钥生成都产生新的公钥和认证随机数

    :return: None, 断言失败表示密钥尺寸或生成行为错误
    """
    first = generate_keys()
    second = generate_keys()
    assert (len(first.public_key), len(first.private_key), len(first.auth_secret)) == (65, 32, 16)
    assert first.public_key != second.public_key
    assert first.auth_secret != second.auth_secret
    assert "private_key=" not in repr(first)


def test_tampering_fails_authentication(registration: Registration) -> None:
    """验证修改密文认证标签必定产生解密错误

    :param registration: 测试密钥
    :return: None, 断言失败表示认证失败未被检测
    """
    data, headers = encrypt_notification(b"message", registration.keys)
    encrypted = decode_base64url(data)
    tampered = encrypted[:-1] + bytes([encrypted[-1] ^ 1])
    with pytest.raises(DecryptionError):
        decrypt_ece(tampered, headers, registration.keys)


@pytest.mark.parametrize("encoding", ["aes128gcm", "aesgcm"])
def test_authenticated_but_invalid_padding_is_decryption_error(registration: Registration, encoding: Literal["aes128gcm", "aesgcm"]) -> None:
    """验证通过认证但填充不完整的记录仍报告统一解密错误

    :param registration: 测试密钥
    :param encoding: 要验证的编码格式
    :return: None, 断言失败表示协议格式异常泄漏或坏填充被接受
    """
    data, headers = encrypt_notification(b"", registration.keys, encoding, padded_plaintext=b"\0")
    with pytest.raises(DecryptionError):
        decrypt_ece(decode_base64url(data), headers, registration.keys)


@pytest.mark.parametrize("encrypted", [b"", b"short", b"\0" * 21])
def test_truncated_content_is_decryption_error(registration: Registration, encrypted: bytes) -> None:
    """验证短密文不会泄漏底层格式异常

    :param registration: 测试密钥
    :param encrypted: 缺少完整内容头的密文
    :return: None, 断言失败表示错误未统一到 DecryptionError
    """
    with pytest.raises(DecryptionError):
        decrypt_ece(encrypted, None, registration.keys)


@pytest.mark.parametrize("data", ["%notbase64", "x", "中文", "a b", "a+b/"])
def test_invalid_base64_is_rejected(data: str) -> None:
    """验证无效字符和不可补齐长度不会进入 ECE 解密

    :param data: 无效 base64url 文本
    :return: None, 断言失败表示非法文本被接受
    """
    with pytest.raises(DecryptionError):
        decode_base64url(data)


def test_content_header_without_authenticated_record_is_rejected(registration: Registration) -> None:
    """验证只有内容头的消息不能被当作已认证的空明文

    :param registration: 测试密钥
    :return: None, 断言失败表示未经认证的内容被成功解密
    """
    data, headers = encrypt_notification(b"message", registration.keys)
    content_header = decode_base64url(data)[:86]
    with pytest.raises(DecryptionError):
        decrypt_ece(content_header, headers, registration.keys)


def test_mismatched_and_short_keys_are_rejected(registration: Registration) -> None:
    """验证配置中的不匹配公钥和短私钥均报告解密错误

    :param registration: 测试密钥
    :return: None, 断言失败表示错误密钥可进入解密流程
    """
    mismatched = replace(registration.keys, public_key=generate_keys().public_key)
    with pytest.raises(DecryptionError, match="does not match"):
        decrypt_ece(b"ciphertext", None, mismatched)
    with pytest.raises(DecryptionError, match="32-byte"):
        decrypt_ece(b"ciphertext", None, replace(registration.keys, private_key=b"short"))


def test_legacy_headers_require_salt_and_sender_key(registration: Registration) -> None:
    """验证旧版编码的必需头缺失时报告明确错误

    :param registration: 测试密钥
    :return: None, 断言失败表示头缺失被静默忽略
    """
    with pytest.raises(DecryptionError, match="missing required header"):
        decrypt_ece(b"ciphertext", {"encoding": "aesgcm"}, registration.keys)
    assert parse_header_param('keyid=one; dh="abc"; p256ecdsa=unused', "dh") == "abc"
    with pytest.raises(DecryptionError, match="not found"):
        parse_header_param("keyid=one", "salt")


def test_unsupported_encoding_is_rejected(registration: Registration) -> None:
    """验证未知编码不能默认为有效密文

    :param registration: 测试密钥
    :return: None, 断言失败表示未知编码被接受
    """
    with pytest.raises(DecryptionError, match="unsupported encoding"):
        decrypt_ece(b"ciphertext", {"encoding": "plaintext"}, registration.keys)
