# 令牌库 (token-vault)

DeepSeek Harness 的本机令牌管理插件。在侧栏「令牌库」面板保存 Git / API 令牌，任意会话用 `vault_sh` 把令牌注入**子进程环境变量**——命令、会话日志、后台任务记录里都看不到值。

## 功能

- **侧栏面板**：新增 / 改名 / 换值 / 启停 / 删除 / 搜索；值写入后不再回显
- **`vault_sh`**：命令里只写 `$GITHUB_TOKEN`；`tokens: ["GITHUB_TOKEN"]` 可只导出点名的令牌
- **输出洗值**：工具输出中出现的令牌值（含 URL 编码、base64、hex、JSON 转义）会被替换回 `{{token:名称}}`
- **落盘加密**（可选）：主密码 + scrypt + AES-256-GCM，Host 重启后上锁，面板解锁
- **审计 / 审批**（可选）：记录谁在哪个会话用了哪个令牌；审批模式下每次 `vault_sh` 先等你确认
- **健康检查 / 有效期**：GitHub、GitLab、npm、Hugging Face、Slack、Cloudflare 有内置端点
- **导入 / 导出**：`.json`、加密 `.tvault`、`.env`；整批校验，一条不合法就整批拒绝
- **agent 权限受限**：只能 `list` 和 `request-save`（发请求，值由你在面板粘贴）

## 用法

面板里填名称（如 `GITHUB_TOKEN`）、值、备注保存，然后在会话里：

```
vault_sh({ description: "check GitHub identity",
           command: 'curl -sS -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user' })
```

Git 推送（令牌只走环境变量，不落进 URL 或 `.git/config`）：

```
vault_sh({ description: "push with token header",
           command: 'GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=http.extraHeader GIT_CONFIG_VALUE_0="Authorization: Basic $(printf \'x-access-token:%s\' "$GITHUB_TOKEN" | base64 -w0)" git push origin main' })
```

**引号注意**：`$GITHUB_TOKEN` 只在双引号或不加引号时展开，单引号里会原样传出去。

**占位符已禁用**：`{{token:名称}}` 不再做参数替换，出现在 `bash` / `run_code` 里会被拒绝（早期版本因此把完整命令行写进过 job 记录）。文档、提示词里它只是普通文本。

## 导入 / 导出

仅在面板操作，agent 没有对应工具。

- **导出**：填密码 → `.tvault`（scrypt + AES-256-GCM）；留空 → `.json` 明文（需输入 `EXPORT` 确认）
- **导入**：`.json` / `.tvault` / `.env`；同名令牌选「保留现有」或「覆盖」
- 上限：单次 500 条、请求体 2 MiB

## 安全

- 所有面板路由都过 `connection` 的认证与来源围栏，未登录/跨站一律 `401`
- **导出是唯一返回值**的路由，只有你点导出才会走到；agent 工具没有任何路径能调用
- 令牌值只存在于 Host 内存、本机文件、`vault_sh` 子进程环境，以及你主动下载的导出文件
- 上锁、审批、停用、审计默认都不强制开启，按需在面板里开

## 文件

| 项 | 位置 |
| --- | --- |
| 令牌库 | `$DSH_HOME/token-vault.json`（`config.file` 可覆盖） |
| 审计日志 | `$DSH_HOME/token-vault-audit.jsonl`（默认开） |
| 审批记录 | `$DSH_HOME/token-vault-approvals.json`（最近 50 条） |
| 加密备份 | `token-vault.json.pre-encryption.bak` |
| 权限 | `0600`，临时文件 + `rename` 原子写 |

## 安装

```
npm i @lls-a1/token-vault
```

仓库自带 `cordis.patch.yml`：在 DSH 的「插件」页面从 npm 或目录安装，装完重启 `dsh web`，侧栏出现「令牌库」。

源码：https://github.com/ming-a1/token-vault

## 限制

- `vault_sh` 的 `timeoutMs` 只对前台生效；后台任务需要 `job_kill` 手动停
- 不支持 `sandbox_permissions` 提权，沿用当前会话的沙箱策略
- 把 `$GITHUB_TOKEN` 拼进 URL 时，git 可能把完整 URL 写进 `.git/config`——建议用上面的 `extraHeader` 写法
- 导出路由返回明文值：同源脚本（含其它客户端插件）在已登录前提下也能调用
- 加密防的是文件被读取，不防本机被完全控制，也不替代吊销令牌

## 版本

见 [tags](https://github.com/ming-a1/token-vault/tags)。近期：`2.0.2` 首发 npm；`2.0.1` 内置 npm 健康检查端点。
