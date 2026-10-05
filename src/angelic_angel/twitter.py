"""
职责: 将 Web Push 订阅注册到 Twitter/X 的通知设置接口
导出: register
依赖: httpx, BeautifulSoup, x_client_transaction, Twitter/X 网络和会话 Cookie
约束: 注册时读取 Web 客户端签名材料, Cookie 仅发送给 x.com
作者: TimeCarol
日期: 2026-10-05 16:34
版本: v1.0
"""

from __future__ import annotations

from typing import cast
from urllib.parse import urlsplit

import httpx
from bs4 import BeautifulSoup
from x_client_transaction import ClientTransaction
from x_client_transaction.utils import generate_headers, get_ondemand_file_url

from angelic_angel.config import Registration, TwitterConfig
from angelic_angel.crypto import encode_base64url
from angelic_angel.errors import HTTPError, TwitterAPIError

# Twitter/X 通知设置 API 根地址, 注册函数只读
TWITTER_API_BASE: str = "https://x.com/i/api/1.1"
# 公开的 Web 客户端 bearer 标识, 用户身份仍由 Cookie 决定
AUTHORIZATION_BEARER: str = "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
# Web Push 设备标识, 作为 os_version 和 udid 发送
DEVICE_ID: str = "Mac/Firefox"
# 通知设置接口中 env=3 表示 Web Push 设备, 注册只读
WEB_PUSH_ENVIRONMENT: int = 3
# Web Push 设备使用的通知协议版本, 注册只读
PUSH_PROTOCOL_VERSION: int = 1
# X Web 客户端的签名材料入口, 注册时只读, 不读取通知数据
X_HOME_URL: str = "https://x.com/home"


async def register(twitter_config: TwitterConfig, push_subscription: Registration) -> None:
    """向 Twitter/X 提交 AutoPush endpoint 和 Web Push 公钥

    :param twitter_config: 当前会话的 auth_token 和 ct0, 不为 None
    :param push_subscription: 完整 AutoPush 订阅, 包含公钥和 auth_secret
    :return: None 表示 HTTP 成功且响应为有效 JSON
    :raises TwitterAPIError: Twitter/X 返回非 2xx 状态
    :raises HTTPError: HTTP 传输, URL, 签名材料或响应 JSON 解析失败
    :副作用: 读取 Web 签名材料并注册远端通知, 不记录 Cookie 或修改配置
    """
    body = {
        "push_device_info": {
            "os_version": DEVICE_ID,
            "udid": DEVICE_ID,
            "env": WEB_PUSH_ENVIRONMENT,
            "locale": "en",
            "protocol_version": PUSH_PROTOCOL_VERSION,
            "token": push_subscription.endpoint,
            "encryption_key1": encode_base64url(push_subscription.keys.public_key),
            "encryption_key2": encode_base64url(push_subscription.keys.auth_secret),
        }
    }
    headers = {
        "Authorization": AUTHORIZATION_BEARER,
        "x-csrf-token": twitter_config.ct0,
        "x-twitter-auth-type": "OAuth2Session",
        "x-twitter-active-user": "yes",
        "x-twitter-client-language": "en",
        "Content-Type": "application/json",
        "Cookie": f"auth_token={twitter_config.auth_token}; ct0={twitter_config.ct0}",
    }
    url = f"{TWITTER_API_BASE}/notifications/settings/login.json"
    try:
        async with httpx.AsyncClient(headers=cast(dict[str, str], generate_headers()), follow_redirects=True, timeout=None) as client:
            headers.update(await _prepare_signed_headers(client, twitter_config, urlsplit(url).path))
            response = await client.post(url, headers=headers, json=body)
        if not response.is_success:
            raise TwitterAPIError(f"push subscription registration failed ({response.status_code}): {response.text}")
        response.json()
    except (httpx.HTTPError, httpx.InvalidURL, ValueError) as error:
        raise HTTPError(f"Twitter push subscription request failed: {error}") from error


async def _prepare_signed_headers(client: httpx.AsyncClient, config: TwitterConfig, path: str) -> dict[str, str]:
    """从 X Web 客户端生成当前请求需要的签名和 CSRF 头

    :param client: 当前注册流程的 HTTP 客户端
    :param config: 用户提供的登录 Cookie
    :param path: API URL 的完整路径, 不含域名或查询参数
    :return: 请求签名, Cookie, CSRF, Origin 和 Referer 头
    :raises HTTPError: 页面, 脚本或签名材料不可用
    :raises httpx.HTTPError: 首页读取失败或返回非 2xx
    :副作用: 读取 x.com 页面和静态脚本, 更新客户端 Cookie jar
    """
    cookie = f"auth_token={config.auth_token}; ct0={config.ct0}"
    # Cookie 作为单次页面请求头发送, 不设为静态脚本域名共享的全局头
    home = await client.get(X_HOME_URL, headers={"Cookie": cookie})
    home.raise_for_status()
    document = BeautifulSoup(home.text, "html.parser")
    try:
        script_url = cast(str, get_ondemand_file_url(document))
        script = await client.get(script_url)
        script.raise_for_status()
        transaction = ClientTransaction(home_page_response=document, ondemand_file_response=script.text)
        transaction_id = cast(str, transaction.generate_transaction_id(method="POST", path=path))
    except Exception as error:
        # 签名库没有稳定的专用异常类型, 所有签名失败均按应用错误向上传播
        raise HTTPError(f"failed to prepare Twitter request signature: {error}") from error
    csrf = home.cookies.get("ct0") or config.ct0
    return {
        "x-client-transaction-id": transaction_id,
        "x-csrf-token": csrf,
        "Cookie": f"auth_token={config.auth_token}; ct0={csrf}",
        "Origin": "https://x.com",
        "Referer": "https://x.com/settings/push_notifications",
    }
