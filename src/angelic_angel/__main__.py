"""
职责: 支持通过 python -m angelic_angel 执行命令行
导出: 模块执行入口
依赖: cli.main, 执行时可能读取配置或访问网络
约束: 导入模块不会运行 CLI
作者: TimeCarol
日期: 2026-10-05 16:23
版本: v1.0
"""

from angelic_angel.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
