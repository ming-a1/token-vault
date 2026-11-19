# 令牌库 (token-vault)

DeepSeek Harness 的本机令牌管理插件。在侧栏「令牌库」面板保存 Git / API 令牌，任意会话用 `vault_sh` 把令牌注入**子进程环境变量**——命令、会话日志、后台任务记录里都看不到值。

## 功能介绍

- **侧栏面板**：新增 / 改名 / 换值 / 启停 / 删除 / 搜索；值写入后不再回显
- **`vault_sh`**：命令里只写 `$GITHUB_TOKEN`；`tokens: ["GITHUB_TOKEN"]` 可只导出点名的令牌
- **输出洗值**：工具输出里的令牌值（含 URL 编码、base64、hex、JSON 转义）会被替换回 `{{token:名称}}`
- **落盘加密**（可选）：主密码 + scrypt + AES-256-GCM，Host 重启后上锁
- **审计 / 审批**（可选）：记录谁在哪个会话用了哪个令牌；审批模式下每次 `vault_sh` 先等你确认
- **健康检查 / 有效期**：GitHub、GitLab、npm、Hugging Face、Slack、Cloudflare 有内置端点
- **导入 / 导出**：`.json`、加密 `.tvault`、`.env`
- **agent 权限受限**：只能 `list` 和 `request-save`（值由你在面板粘贴）

## 使用方法

1. 打开侧栏「令牌库」，填名称（如 `GITHUB_TOKEN`）、令牌值、备注，保存
2. 在会话里用 `vault_sh` 跑需要令牌的命令：

```
vault_sh({ description: "check GitHub identity",
           command: 'curl -sS -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user' })
```

Git 推送（令牌只走环境变量，不落进 URL 或 `.git/config`）：

```
vault_sh({ description: "push with token header",
           command: 'GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=http.extraHeader GIT_CONFIG_VALUE_0="Authorization: Basic $(printf \'x-access-token:%s\' "$GITHUB_TOKEN" | base64 -w0)" git push origin main' })
```

- 只要部分令牌：`vault_sh({ ..., tokens: ["GITHUB_TOKEN"] })`
- `$NAME` 只在双引号或不加引号时展开，单引号里会原样传出去
- `{{token:名称}}` 占位符已停用，写在 `bash` / `run_code` 里会被拒绝

## 安装

```
npm i @lls-a1/token-vault
```

在 DSH 的「插件」页面从 npm 或本地目录安装，装完重启 `dsh web`，侧栏出现「令牌库」入口。

源码与版本：https://github.com/ming-a1/token-vault
