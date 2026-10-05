"""
职责: 验证配置完整性, 凭据交互和命令行操作的失败边界
导出: pytest 测试函数
依赖: pytest, 临时 TOML 文件, CLI 控制台捕获
约束: 使用虚构凭据, 不访问生产服务
作者: TimeCarol
日期: 2026-10-05 16:42
版本: v1.0
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from angelic_angel import autopush, cli, listener, push, twitter
from angelic_angel.config import Config, Registration, TwitterConfig, get_webhook_endpoint
from angelic_angel.errors import ConfigError, TwitterAPIError


def test_config_preserves_byte_arrays_and_registration(config_path: Path, registration: Registration) -> None:
    """验证完整订阅往返读写且密钥保持整数数组

    :param config_path: 完整测试配置
    :param registration: 对应测试订阅
    :return: None, 断言失败表示配置丢失数据
    """
    config = Config.load(config_path)
    assert config.registration == registration
    config.save(config_path)
    assert Config.load(config_path) == config
    document = tomllib.loads(config_path.read_text())
    assert document["registration"]["keys"]["public_key"] == list(registration.keys.public_key)


@pytest.mark.parametrize("content", [
    "[twitter]\nauth_token='token'", "twitter = []", "[twitter]\nauth_token=3\nct0='csrf'", "[[[broken",
    "[twitter]\nauth_token='t'\nct0='c'\n[registration]\nendpoint='e'",
])
def test_invalid_config_reports_file_path(tmp_path: Path, content: str) -> None:
    """验证缺失字段和错误 TOML 能定位到具体文件

    :param tmp_path: 临时目录
    :param content: 无效配置样例
    :return: None, 断言失败表示校验或错误上下文缺失
    """
    path = tmp_path / "broken.toml"
    path.write_text(content)
    with pytest.raises(ConfigError, match="broken.toml"):
        Config.load(path)


@pytest.mark.parametrize("invalid_byte", [-1, 256, True, "12"])
def test_key_array_rejects_non_byte_values(config_path: Path, invalid_byte: object) -> None:
    """验证密钥数组拒绝越界整数及布尔值

    :param config_path: 已有完整配置
    :param invalid_byte: 待拒绝的数组元素
    :return: None, 断言失败表示非法密钥被接受
    """
    content = config_path.read_text()
    content = content[:content.index("public_key =")] + f"public_key = [{repr(invalid_byte).lower()}]\nprivate_key=[]\nauth_secret=[]\n"
    config_path.write_text(content)
    with pytest.raises(ConfigError):
        Config.load(config_path)


def test_cli_init_and_status_hide_credentials(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """验证初始化可读取参数且状态输出不会暴露凭据

    :param tmp_path: 临时目录
    :param capsys: 输出捕获 fixture
    :return: None, 断言失败表示命令或脱敏不正确
    """
    path = tmp_path / "init.toml"
    assert cli.main(["init", "--auth-token", "私密token", "--ct0", "私密csrf", "-c", str(path)]) == 0
    assert Config.load(path).twitter == TwitterConfig("私密token", "私密csrf")
    assert cli.main(["-c", str(path), "status"]) == 0
    output = capsys.readouterr().err
    assert "not registered" in output
    assert "私密" not in output


def test_cli_interactive_init(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """验证未传入 Cookie 时调用交互输入

    :param tmp_path: 临时目录
    :param monkeypatch: 替换输入函数以避免真实交互
    :return: None, 断言失败表示交互数据未保存
    """
    monkeypatch.setattr("angelic_angel.cli.getpass.getpass", lambda prompt: "hidden-token")
    monkeypatch.setattr("builtins.input", lambda prompt: "csrf-token")
    path = tmp_path / "interactive.toml"
    assert cli.main(["init", "-c", str(path)]) == 0
    assert Config.load(path).twitter == TwitterConfig("hidden-token", "csrf-token")


def test_cli_register_and_unregister_update_config(config_path: Path, registration: Registration, monkeypatch: pytest.MonkeyPatch) -> None:
    """验证注册和注销在远端操作成功后保存对应状态

    :param config_path: 测试配置
    :param registration: 模拟注册结果
    :param monkeypatch: 替换网络调用
    :return: None, 断言失败表示持久化状态错误
    """
    subscribe = AsyncMock(return_value=registration)
    register = AsyncMock()
    unregister = AsyncMock()
    monkeypatch.setattr(push, "subscribe", subscribe)
    monkeypatch.setattr(twitter, "register", register)
    monkeypatch.setattr(autopush, "unregister", unregister)
    assert cli.main(["register", "-c", str(config_path)]) == 0
    register.assert_awaited_once()
    assert Config.load(config_path).registration == registration
    assert cli.main(["unregister", "-c", str(config_path)]) == 0
    unregister.assert_awaited_once_with(registration.autopush)
    assert Config.load(config_path).registration is None


def test_failed_registration_does_not_overwrite_config(config_path: Path, registration: Registration, monkeypatch: pytest.MonkeyPatch) -> None:
    """验证 Twitter/X 拒绝注册时配置保持此前有效状态

    :param config_path: 已保存的配置
    :param registration: 模拟新订阅
    :param monkeypatch: 替换订阅和注册调用
    :return: None, 断言失败表示失败注册污染配置
    """
    before = config_path.read_bytes()
    monkeypatch.setattr(push, "subscribe", AsyncMock(return_value=registration))
    monkeypatch.setattr(twitter, "register", AsyncMock(side_effect=TwitterAPIError("HTTP 403")))
    assert cli.main(["-c", str(config_path), "register"]) == 1
    assert config_path.read_bytes() == before


def test_listen_requires_registration(tmp_path: Path) -> None:
    """验证监听在缺少订阅时返回错误退出码

    :param tmp_path: 临时配置目录
    :return: None, 断言失败表示未注册状态被允许监听
    """
    path = tmp_path / "config.toml"
    Config(TwitterConfig("token", "csrf")).save(path)
    assert cli.main(["listen", "-c", str(path)]) == 1


def test_status_distinguishes_missing_and_invalid_config(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """验证不存在的配置显示提示而损坏的配置报告失败

    :param tmp_path: 临时目录
    :param capsys: 输出捕获 fixture
    :return: None, 断言失败表示损坏配置被误报为未初始化
    """
    path = tmp_path / "config.toml"
    assert cli.main(["status", "-c", str(path)]) == 0
    assert "not found" in capsys.readouterr().err
    path.write_text("bad TOML")
    assert cli.main(["status", "-c", str(path)]) == 1


def test_global_options_work_after_subcommand() -> None:
    """验证全局参数可放在子命令之后

    :return: None, 断言失败表示参数被子命令默认值覆盖
    """
    before = cli.parse_args(["-v", "-c", "custom.toml", "status"])
    after = cli.parse_args(["status", "-v", "-c", "custom.toml"])
    assert before == after
    assert before.verbose
    assert before.config_path == Path("custom.toml")


def test_missing_webhook_variable_is_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    """验证缺少 webhook 环境变量时给出可定位错误

    :param monkeypatch: 环境变量修改 fixture
    :return: None, 断言失败表示缺省值隐藏配置错误
    """
    monkeypatch.delenv("WEBHOOK_ENDPOINT", raising=False)
    with pytest.raises(ConfigError, match="WEBHOOK_ENDPOINT"):
        get_webhook_endpoint()


def test_ctrl_c_returns_clean_exit(config_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """验证监听取消能够返回可控退出码

    :param config_path: 已注册配置
    :param monkeypatch: 替换监听操作模拟用户中断
    :return: None, 断言失败表示中断传播到命令行栈
    """
    monkeypatch.setattr(listener, "listen", AsyncMock(side_effect=KeyboardInterrupt))
    assert cli.main(["listen", "-c", str(config_path)]) == 0
