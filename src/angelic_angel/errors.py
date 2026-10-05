"""
职责: 定义调用方可以区分的配置, 协议, 解密及网络错误
导出: AngelicAngelError, ConfigError, AutoPushError, ServerBackoffError, ReregistrationError, DecryptionError, TwitterAPIError, HTTPError
依赖: 无 IO, 异常实例保留失败原因
约束: 重连逻辑使用异常类型判断恢复策略
作者: TimeCarol
日期: 2026-10-05 16:23
版本: v1.0
"""


class AngelicAngelError(Exception):
    """表示应用可预期的失败, 不处理异常或持有资源

    实例由抛出方创建, 接收方只读取错误消息, 无共享可变状态
    """


class ConfigError(AngelicAngelError):
    """表示配置读写或字段校验失败, 不执行自动修复

    实例仅携带错误上下文, 生命周期由异常传播管理
    """


class AutoPushError(AngelicAngelError):
    """表示 AutoPush 连接或协议失败, 不决定重试时间

    实例由协议层创建, listener 按连接阶段决定是否重试
    """


class ServerBackoffError(AutoPushError):
    """表示服务端通过关闭码 4774 请求延迟重连, 不自行休眠

    实例为不可共享的错误信号, listener 必须遵循 30 分钟退避
    """


class ReregistrationError(AutoPushError):
    """表示 UAID 更新后的订阅恢复失败, 不继续使用旧订阅

    实例由恢复流程创建, listener 将其视为需要用户处理的终止错误
    """


class DecryptionError(AngelicAngelError):
    """表示密文, 密钥或 UTF-8 消息无效, 不隐藏原始异常链

    实例在通知处理完成后释放, 对应 AutoPush ACK 101
    """


class TwitterAPIError(AngelicAngelError):
    """表示 Twitter/X 拒绝订阅注册, 不修改持久化配置

    实例保留 HTTP 状态及响应上下文, 由 CLI 或恢复流程处理
    """


class HTTPError(AngelicAngelError):
    """表示 HTTP 传输或响应解析失败, 不负责请求重试

    实例由 HTTP 调用方创建, webhook 传输失败对应 ACK 102
    """
