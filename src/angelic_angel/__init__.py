"""
职责: 提供 Angelic Angel Python 包及版本信息
导出: __version__
依赖: 无 IO 或全局状态修改
约束: Python 3.11 及以上, 网络操作仅在显式调用时执行
作者: TimeCarol
日期: 2026-10-05 16:23
版本: v1.0
"""

# 包版本由 CLI 和使用方读取, 与 pyproject.toml 的发布版本保持一致
__version__: str = "0.1.0"
