# Clawdbot 企业微信插件

企业微信 (WeCom) 消息渠道插件，让你可以通过企业微信与 Clawdbot AI 助手对话。

## 功能

- 接收企业微信消息并转发给 AI 处理
- 支持 AES-256-CBC 加密消息解密
- 支持应用菜单快捷命令
- 支持多账户配置

## 安装

```bash
# 克隆到插件目录
git clone https://github.com/dee-lii/clawdbot-plugin-wecom ~/.clawdbot/plugins/wecom
```

## 配置

在 `~/.clawdbot/clawdbot.json` 中添加：

```json
{
  "plugins": {
    "allow": ["wecom"],
    "load": {
      "paths": ["~/.clawdbot/plugins/wecom"]
    },
    "entries": {
      "wecom": {
        "config": {
          "corpId": "你的企业ID",
          "corpSecret": "应用Secret",
          "agentId": "应用AgentId",
          "token": "回调Token",
          "encodingAesKey": "回调EncodingAESKey"
        }
      }
    }
  }
}
```

## 企业微信配置

1. 登录 [企业微信管理后台](https://work.weixin.qq.com/)
2. 创建自建应用
3. 在应用设置中配置：
   - **接收消息 URL**: `https://你的域名/webhooks/wecom`
   - **Token**: 自定义，填入配置
   - **EncodingAESKey**: 随机生成，填入配置

## 应用菜单

插件会自动创建以下菜单：

| 菜单 | 功能 |
|------|------|
| 新对话 | 重置会话 (/reset) |
| 压缩上下文 | 压缩对话历史 (/compact) |
| 切换模型 | 切换 AI 模型 (/model) |
| 帮助 | 查看帮助 (/help) |

## CLI 命令

```bash
# 重新创建菜单
clawdbot wecom menu

# 查看状态
clawdbot wecom status
```

## 许可证

MIT
