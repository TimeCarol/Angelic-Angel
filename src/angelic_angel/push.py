"""
职责: 生成 Web Push 接收端密钥并建立新的推送订阅
导出: generate_keys, subscribe
依赖: cryptography, 系统安全随机数, AutoPush 网络注册
约束: 每次订阅都生成新密钥, 私钥使用 32 字节原始标量
作者: TimeCarol
日期: 2026-10-05 16:25
版本: v1.0
"""

from __future__ import annotations

import secrets

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from angelic_angel import autopush
from angelic_angel.config import AUTH_SECRET_BYTES, P256_PRIVATE_KEY_BYTES, Registration, WebPushKeys


def generate_keys() -> WebPushKeys:
    """生成新的 ECDH P-256 密钥及认证随机数

    :return: 65 字节公钥, 32 字节私钥和 16 字节 auth_secret
    :副作用: 消耗系统安全随机数, 不写文件或复用旧密钥
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    return WebPushKeys(
        public_key=private_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint),
        private_key=private_key.private_numbers().private_value.to_bytes(P256_PRIVATE_KEY_BYTES, "big"),
        auth_secret=secrets.token_bytes(AUTH_SECRET_BYTES),
    )


async def subscribe() -> Registration:
    """创建 AutoPush 订阅并附带对应的接收端密钥

    :return: 可直接传给 Twitter/X 注册和配置保存的完整订阅
    :raises AutoPushError: AutoPush 网络或协议注册失败
    :副作用: 生成随机密钥并注册远端通道, 返回前关闭注册连接
    """
    return await autopush.register_new(generate_keys())
