"""
职责: 提供配置, 注册, 监听, 状态和注销命令及应用退出码
导出: main, parse_args, Options
依赖: argparse, 控制台交互, TOML 文件和按命令触发的网络请求
约束: 凭据交互不回显 auth_token, Ctrl+C 取消异步操作并关闭连接
作者: TimeCarol
日期: 2026-10-05 16:34
版本: v1.0
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, TypeAlias, cast

from angelic_angel import __version__, autopush, listener, push, twitter
from angelic_angel.config import Config, TwitterConfig
from angelic_angel.errors import AngelicAngelError, ConfigError

# CLI 子命令集合, parse_args 写入, 分派函数只读
Command: TypeAlias = Literal["init", "register", "listen", "status", "unregister"]
# 当前目录下的默认配置名, 参数解析只读
DEFAULT_CONFIG_PATH: str = "angelic-angel.toml"


@dataclass(frozen=True)
class Options:
    """持有已解析的命令行选项, 不执行命令

    实例不可变, parse_args 创建并由主入口持有, command 必须为五个合法命令之一

    :param config_path: TOML 配置路径
    :param verbose: 是否启用 debug 日志
    :param command: 要执行的命令
    :param auth_token: init 的可选登录 Cookie, None 表示交互输入
    :param ct0: init 的可选 CSRF Cookie, None 表示交互输入
    """

    # 参数解析时写入, 所有命令读取, 默认路径由 parser 决定
    config_path: Path
    # 参数解析时写入, 日志初始化读取, 默认关闭以免产生过多输出
    verbose: bool
    # 参数解析时写入, 分派读取, 无默认值以强制选择操作
    command: Command
    # init 参数解析时写入, 默认 None 启用隐藏输入
    auth_token: str | None = None
    # init 参数解析时写入, 默认 None 启用控制台输入
    ct0: str | None = None


def parse_args(argv: Sequence[str] | None = None) -> Options:
    """解析命令及全局配置参数

    :param argv: 不含程序名的参数序列, None 表示读取 sys.argv
    :return: 不可变参数对象, 全局参数可放在子命令前后
    :raises SystemExit: 请求帮助或版本时退出 0, 非法参数时退出 2
    :副作用: argparse 可能向标准输出或错误输出打印帮助
    """
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--config", default=argparse.SUPPRESS, help="Configuration file path")
    common.add_argument("-v", "--verbose", action="store_true", default=argparse.SUPPRESS, help="Enable debug logs")
    parser = argparse.ArgumentParser(prog="angelic-angel", description="Twitter Web Push Receiver", parents=[common])
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subcommands = parser.add_subparsers(dest="command", required=True)
    init_parser = subcommands.add_parser("init", parents=[common], help="Initialize configuration")
    init_parser.add_argument("--auth-token", help="Twitter auth_token Cookie")
    init_parser.add_argument("--ct0", help="Twitter ct0 Cookie")
    for name, description in {
        "register": "Register AutoPush and Twitter/X subscription",
        "listen": "Listen for push notifications",
        "status": "Show configuration and registration status",
        "unregister": "Remove AutoPush subscription",
    }.items():
        subcommands.add_parser(name, parents=[common], help=description)
    arguments = parser.parse_args(argv)
    return Options(
        config_path=Path(arguments.config if hasattr(arguments, "config") else DEFAULT_CONFIG_PATH),
        verbose=cast(bool, getattr(arguments, "verbose", False)),
        command=cast(Command, arguments.command),
        auth_token=cast(str | None, getattr(arguments, "auth_token", None)),
        ct0=cast(str | None, getattr(arguments, "ct0", None)),
    )


def main(argv: Sequence[str] | None = None) -> int:
    """执行命令并返回应用退出码

    :param argv: 不含程序名的参数序列, None 表示使用进程参数
    :return: 成功或 Ctrl+C 返回 0, 应用错误返回 1
    :raises SystemExit: 参数解析阶段的帮助或用法错误
    :副作用: 配置日志和事件循环, 按子命令执行文件或网络操作
    """
    options = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if options.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # 网络库的 DEBUG 可能打印 Cookie, verbose 只展开本应用日志
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("websockets").setLevel(logging.WARNING)
    try:
        asyncio.run(_execute(options))
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        return 0
    except AngelicAngelError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


async def _execute(options: Options) -> None:
    """按命令分派配置和网络操作

    :param options: 已校验的 CLI 参数
    :return: None 表示命令执行完成
    :raises AngelicAngelError: 配置, 注册或监听失败
    :副作用: 执行选定命令的文件或网络操作
    """
    if options.command == "init":
        _initialize(options)
        return
    if options.command == "status":
        _show_status(options.config_path)
        return
    config = Config.load(options.config_path)
    if options.command == "register":
        print("Registering push subscription", file=sys.stderr)
        subscription = await push.subscribe()
        await twitter.register(config.twitter, subscription)
        config.registration = subscription
        config.save(options.config_path)
        print(f"done Saved to {options.config_path}", file=sys.stderr)
        return
    registration = config.registration
    if registration is None:
        raise ConfigError("No registration found. Run `register` first.")
    if options.command == "listen":
        await listener.listen(registration, options.config_path)
        return
    await autopush.unregister(registration.autopush)
    config.registration = None
    config.save(options.config_path)
    print(f"done Registration removed from {options.config_path}", file=sys.stderr)


def _initialize(options: Options) -> None:
    """写入初始化凭据并清除旧注册状态

    :param options: init 参数, 缺少凭据时交互读取
    :return: None 表示配置保存完成
    :raises ConfigError: 输入中断或文件写入失败
    :副作用: 读取终端并覆盖配置, 再次初始化会清除本地旧订阅
    """
    print("Initializing configuration", file=sys.stderr)
    try:
        auth_token = options.auth_token if options.auth_token is not None else getpass.getpass("auth_token: ")
        ct0 = options.ct0 if options.ct0 is not None else input("ct0: ")
    except (EOFError, OSError) as error:
        raise ConfigError(f"credential input failed: {error}") from error
    Config(TwitterConfig(auth_token, ct0)).save(options.config_path)
    print(f"done Saved to {options.config_path}", file=sys.stderr)


def _show_status(config_path: Path) -> None:
    """显示配置与订阅状态而不暴露完整凭据

    :param config_path: 需要检查的配置路径
    :return: None, 未初始化也视为正常状态查询
    :raises ConfigError: 已存在文件无法读取或配置无效
    :副作用: 读取配置并向标准错误输出状态, 不访问网络
    """
    print("Status", file=sys.stderr)
    if not config_path.exists():
        print("Config  not found\n  Run angelic-angel init to initialize.", file=sys.stderr)
        return
    config = Config.load(config_path)
    print(f"Config  {config_path}", file=sys.stderr)
    print(f"  auth_token  {'***' if config.twitter.auth_token else '(empty)'}", file=sys.stderr)
    print(f"  ct0         {'***' if config.twitter.ct0 else '(empty)'}", file=sys.stderr)
    registration = config.registration
    if registration is None:
        print("Registration  not registered\n  Run angelic-angel register to register.", file=sys.stderr)
        return
    print("Registration  active", file=sys.stderr)
    print(f"  endpoint    {registration.endpoint[:50]}...", file=sys.stderr)
    print(f"  uaid        {registration.autopush.uaid}", file=sys.stderr)
    print(f"  channel_id  {registration.autopush.channel_id}", file=sys.stderr)
