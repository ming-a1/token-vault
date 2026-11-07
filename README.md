# 令牌库 (token-vault)

给 DeepSeek Harness 用的本机令牌管理插件：在侧栏的**令牌库**面板里保存 Git 令牌或其他 API 令牌，任意会话用 `vault_sh` 工具跑命令时把令牌注入**子进程环境变量**，令牌值不会出现在命令、会话记录、后台任务记录里。

## 能做什么

- **侧栏面板**：名称 / 令牌值 / 备注 三项录入；列表显示令牌名、备注、`•••••••• · N 个字符`、更新时间
- **只写不读**：面板可以新增、替换值、改备注、删除（二次确认）；除显式的「导出」动作外，**没有任何接口返回令牌值**
- **导入 / 导出**：一键导出全部令牌为文件，可选密码加密（scrypt + AES-256-GCM）；导入支持明文 `.json` 与加密 `.tvault`，同名令牌可选「保留现有」或「覆盖」
- **会话零暴露**：agent 工具 `token_vault` 只返回令牌名、备注、长度；`vault_sh` 只把值放进子进程环境，命令文本里只有 `$GITHUB_TOKEN`
- **输出洗值**：工具输出里出现的任何已存令牌值（含 URL 编码形式）会被替换回 `{{token:名称}}`，`echo`、报错信息也泄不出去
- **占位符已禁用**：`{{token:名称}}` 不再做参数替换；出现在 `bash` / `run_code` 调用里会被拒绝并提示改用 `vault_sh`（其它工具、文档、提示词里它只是普通文本）
- **自动提示**：系统提示段落列出令牌名与备注（不含值）和 `vault_sh` 的用法，新会话不用先查询
- 中英双语界面，跟随 Harness 的语言设置

## 用法

1. 打开侧栏的 **令牌库**，填名称（如 `GITHUB_TOKEN`）、令牌值、备注，保存
2. 需要令牌时用 `vault_sh` 跑命令，令牌以环境变量形式存在于子进程：

   ```
   vault_sh({ description: "check GitHub identity",
              command: 'curl -sS -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user' })
   ```

3. 命令文本、工具调用记录、后台任务标签、回执里都只有 `$GITHUB_TOKEN`；值只在该子进程的环境里

**引号注意**：`$GITHUB_TOKEN` 用双引号或不加引号才会展开，单引号里 shell 不展开变量（`'Bearer $GITHUB_TOKEN'` 会原样传出去）。需要单引号的场合请改成双引号并转义内部引号。

Git 推送示例（令牌只走环境变量，不落进 URL 或 `.git/config`）：

```
vault_sh({ description: "push with token header",
           command: 'GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=http.extraHeader GIT_CONFIG_VALUE_0="Authorization: Basic $(printf \'x-access-token:%s\' "$GITHUB_TOKEN" | base64 -w0)" git push origin main' })
```

需要点名时，让 agent 调用 `token_vault` 工具列出当前可用的令牌（名称、备注、长度）。

## 导入 / 导出

面板底部是「导入 / 导出」区，**只由用户操作**，agent 没有对应工具。

**导出**

- 填「导出密码」→ 生成 `.tvault` 加密文件；留空 → 生成 `.json` 明文文件（会二次确认）
- 加密参数：`scrypt(N=16384, r=8, p=1, keylen=32)` 派生密钥，`AES-256-GCM` 加密，16 字节随机盐、12 字节随机 IV，认证标签单独存放；密码错或文件损坏都会直接报错，不会解出半截数据
- 文件名形如 `token-vault-2026-11-07T09-30-00.tvault`，由浏览器直接下载

**导入**

- 选文件 → 填文件密码（明文文件留空）→ 选同名策略 → 导入
- `保留现有`：已存在的令牌完全不动，只新增；`覆盖`：同名令牌的值和备注被文件里的内容替换（保留原创建时间）
- 整批校验：只要有一个条目的名称/值不合法，**整个导入被拒绝**，不会出现导入一半的库
- 单次最多 500 条、请求体上限 2 MiB

明文导出文件格式：

```json
{
  "format": "token-vault/export",
  "version": 1,
  "exportedAt": "2026-11-07T01:30:00.000Z",
  "tokens": [{ "name": "GITHUB_TOKEN", "value": "…", "note": "…" }]
}
```

## 安全设计

- 面板的五条路由（list / save / delete / export / import）挂在 GUI 的 HTTP 服务上，每条都先过 `connection` 的认证与来源围栏：未登录或跨站请求直接 `401`
- **导出是唯一返回值的那条路由**（`POST /token-vault/export`），只有用户在面板里点「导出」才会走到；agent 工具没有任何路径能调用它
- 令牌值只存在于 Host 进程内存、本机文件、`vault_sh` 子进程环境，以及用户主动下载的导出文件里；工具结果和系统提示里都没有它
- **不再改写工具参数**：早期版本把 `{{token:名称}}` 在派发前替换成真实值，结果 bash 工具会把「替换后的完整命令行」写进会话日志的 `job/registered` 事件（作为 job 标签），并随 `job_output` / 任务回执回到会话里——后台任务和普通 bash 调用都会这样。1.1.0 起彻底去掉参数替换，改为环境变量注入
- `bash` / `run_code` 里出现占位符会被 `tools/pre-execute` 拒绝，避免「以为会被替换、实际原样执行」
- 洗值下限 8 个字符，避免误伤普通文本；较长的值优先匹配，防止前缀吞掉整串
- 名称受限为 `^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`；名字里的 `.`、`-` 在导出环境变量时会换成 `_`

## 文件与配置

| 项 | 值 |
| --- | --- |
| 存储文件 | `$DSH_HOME/token-vault.json`（默认 `~/.dsh/token-vault.json`） |
| 覆盖路径 | 插件行配置 `config.file` 填绝对路径 |
| 权限 | `0600`；写入用临时文件 + `rename` 原子替换 |
| 名称规则 | 字母或下划线开头，最长 64 字符 |
| 令牌值上限 | 8192 字符 |
| 备注上限 | 500 字符 |

多会话、多 profile 共用同一个文件：令牌是「这个人」的凭据，而不是某个工作区的凭据。

## 安装

本包自带 `cordis.patch.yml`，作为本地 bundle 装进当前 profile 即可：把仓库目录交给 DeepSeek Harness 的插件管理（「插件」页面里的本地目录安装），它会插入 `token-vault` 这一行并启用。装好刷新页面，侧栏就会出现「令牌库」入口（不再另外占用设置里的位置）。

- 主机半：`index.js`——存储、HTTP 路由、`token_vault` / `vault_sh` 工具、占位符拦截、系统提示段落
- 浏览器半：`client.js`——侧栏令牌库面板
- 资源：[`locale/en.json`](locale/en.json)、[`locale/zh.json`](locale/zh.json)、[`icon.svg`](icon.svg)

## 已知限制

- **明文存储**：令牌以明文 JSON 存在本机 `0600` 文件里，没有加密。本机账户被攻破时令牌会暴露
- `vault_sh` 走前台执行（`onExpiry: 'kill'`）：长任务请用 `timeoutMs`，或在命令内部后台化（`nohup … &`）；它不注册后台 job，因此也没有 `job_output`
- `vault_sh` 不支持 `sandbox_permissions` 提权：它沿用当前会话的沙箱策略
- 把 `$GITHUB_TOKEN` 拼进 URL（如 `https://oauth2:$GITHUB_TOKEN@github.com/...`）时，git 可能把完整 URL 写进 `.git/config` 或错误信息；错误信息会被洗值，`.git/config` 不会——建议用上面的 `http.extraHeader` 写法
- 面板只用 Harness 的主题 token 做了配色适配，没有做截图级视觉回归
- **同源脚本风险**：导出路由返回全部令牌值，任何运行在这个页面同源下的脚本（包括其它客户端插件）都能在已登录前提下调用它。这是浏览器内导出绕不开的取舍；不装来路不明的客户端插件是前提
- 加密导出的保护对象是「文件在磁盘/传输中被读取」；它不防本机被完全控制，也不替代吊销令牌
- 明文导出的文件就是明文凭据，导出后请自行保管或及时删除

## 版本

- `1.3.3`：导入 / 导出改为左右两栏，中间竖分割线，窄屏自动上下堆叠
- `1.3.2`：重排「导入 / 导出」布局，导出、导入各成一组，控件统一 32px 高、单行排布
- `1.3.1`：文件选择改成面板风格按钮（隐藏原生 `<input type="file">`），不再出现浏览器原生控件
- `1.3.0`：新增导入 / 导出，导出可选密码加密（scrypt + AES-256-GCM），导入支持合并与覆盖
- `1.2.x`：面板从设置移到侧栏（1.2.1），窄屏行内布局修正（1.2.2）
- `1.1.0`：**安全修复**——去掉工具参数的占位符替换（会经 `job/registered` 泄漏完整命令行），改为 `vault_sh` 环境变量注入；`bash` / `run_code` 里的占位符直接拒绝
- `1.0.1`：`write` / `edit` 参数不再做占位符替换与未知令牌拦截，便于写文档和模板
- `1.0.0`：首个版本
