/**
 * Token vault — the browser half.
 *
 * Renders the "Token vault" page inside Settings. The page is the only place
 * tokens are written: it lists names, notes and value lengths (never values),
 * and every operation goes to the Host routes the package's other half serves.
 *
 * The page also hosts the vault's security state (master-password encryption
 * with unlock/lock, approval mode, the audit toggle), the pending
 * confirmations (agent save requests and vault_sh command approvals), a
 * `.env` bulk import, per-token health checks and search.
 *
 * @module @lls-a1/token-vault/client
 */

window.__ModuleLoader__.load({
  id: '@lls-a1/token-vault',
  factory(require) {
    const React = require('react')
    const { useCallback, useEffect, useRef, useState, useSyncExternalStore } = React
    const h = React.createElement

    const LOCALE_NS = 'token-vault'
    const LIST_ROUTE = 'token-vault/list'
    const EXPORT_ROUTE = 'token-vault/export'
    const IMPORT_ROUTE = 'token-vault/import'
    const IMPORT_ENV_ROUTE = 'token-vault/import-env'
    const SAVE_ROUTE = 'token-vault/save'
    const DELETE_ROUTE = 'token-vault/delete'
    const RENAME_ROUTE = 'token-vault/rename'
    const SETTINGS_ROUTE = 'token-vault/settings'
    const ENCRYPT_ROUTE = 'token-vault/encrypt'
    const DISABLE_ENCRYPTION_ROUTE = 'token-vault/disable-encryption'
    const UNLOCK_ROUTE = 'token-vault/unlock'
    const LOCK_ROUTE = 'token-vault/lock'
    const DELETE_BACKUP_ROUTE = 'token-vault/delete-backup'
    const PENDING_ROUTE = 'token-vault/pending'
    const HISTORY_ROUTE = 'token-vault/history'
    const HISTORY_CLEAR_ROUTE = 'token-vault/history/clear'
    const HISTORY_DELETE_ROUTE = 'token-vault/history/delete'
    const RESOLVE_ROUTE = 'token-vault/resolve'
    const REVOKE_GRANT_ROUTE = 'token-vault/revoke-grant'
    const CHECK_ROUTE = 'token-vault/check'
    const NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/
    const EXPORT_CONFIRMATION = 'EXPORT'
    /** Mirrors the Host's approval timeout, used for the countdown fallback. */
    const APPROVAL_TIMEOUT_MS = 120_000
    const PENDING_POLL_MS = 3000

    /** Token-value prefixes the panel recognises to prefill a name and a check URL. */
    const PREFIX_HINTS = [
      [/^ghp_|^gho_|^ghu_|^ghs_|^github_pat_/, { name: 'GITHUB_TOKEN', check: 'https://api.github.com/user', note: 'GitHub' }],
      [/^glpat-/, { name: 'GITLAB_TOKEN', check: 'https://gitlab.com/api/v4/user', note: 'GitLab' }],
      [/^xox[baprs]-/, { name: 'SLACK_TOKEN', note: 'Slack' }],
      [/^AKIA/, { name: 'AWS_ACCESS_KEY_ID', note: 'AWS access key id' }],
      [/^hf_/, { name: 'HUGGINGFACE_TOKEN', note: 'Hugging Face' }],
      [/^sk-/, { name: 'LLM_API_KEY', note: 'OpenAI/DeepSeek style API key' }],
    ]

    const DICTIONARIES = {
      en: {
        nav: 'Token vault',
        lead:
          'Tokens live in a local file on this machine and never appear in a session: the vault exports one into a command\'s environment, and tool output is scrubbed if a command echoes it.',
        'field.name': 'Name',
        'field.namePlaceholder': 'e.g. GITHUB_TOKEN',
        'field.value': 'Token value',
        'field.valuePlaceholder': 'Paste the token — it is never shown again',
        'field.note': 'Note',
        'field.notePlaceholder': 'What this token is for (optional)',
        'field.newValue': 'New value',
        'field.keepValue': 'Leave blank to keep the current value',
        'field.checkUrl': 'Check URL (optional)',
        'field.checkUrlPlaceholder': 'e.g. https://api.github.com/user',
        'field.expires': 'Expires (optional)',
        'field.envFile': 'From .env file',
        'action.save': 'Save token',
        'action.saving': 'Saving…',
        'action.saveChanges': 'Save',
        'action.cancel': 'Cancel',
        'action.copyVariable': 'Copy $NAME',
        'action.copied': 'Copied',
        'action.replace': 'Replace value',
        'action.rename': 'Rename',
        'action.check': 'Test',
        'action.checking': 'Testing…',
        'action.delete': 'Delete',
        'action.confirmDelete': 'Confirm delete',
        'action.approve': 'Approve',
        'action.deny': 'Deny',
        'action.enable': 'Enabled',
        'tab.tokens': 'Tokens',
        'tab.pending': 'Approvals',
        'tab.security': 'Security',
        'tab.transfer': 'Import / export',
        'list.title': 'Stored tokens',
        'list.count': '{count} total',
        'list.loading': 'Loading…',
        'list.empty': 'No tokens yet — add one above.',
        'list.searchPlaceholder': 'Filter by name or note…',
        'list.searchEmpty': 'No token matches the filter.',
        'row.hidden': '•••••••• · {count} characters',
        'row.neverUsed': 'never used',
        'row.lastUsed': 'last used {when}',
        'row.usedBy': ' by {who}',
        'row.expired': 'expired {when}',
        'row.expiresSoon': 'expires in {days}d',
        'row.disabled': 'disabled',
        'check.ok': 'OK ({status})',
        'check.unauthorized': 'rejected ({status} — likely expired)',
        'check.other': 'status {status}',
        'error.nameRequired': 'Enter a name.',
        'error.nameInvalid': 'Start with a letter or underscore; then letters, digits, dot, dash or underscore.',
        'error.valueRequired': 'Enter the token value.',
        'error.copyFailed': 'The clipboard is not available in this browser.',
        'error.exportConfirm': 'Type EXPORT into the confirmation field to export without a password.',
        'notice.saved': 'Saved {name}.',
        'notice.updated': 'Updated {name}.',
        'notice.deleted': 'Deleted {name}.',
        'notice.renamed': 'Renamed to {name}.',
        'notice.duplicate': 'This value already exists as {names} — consider updating that token instead.',
        'hint.prefix': 'Recognised {provider} token — prefilled the name; save first, then set a check URL if you like.',
        'pending.cardTitle': 'A call wants to use your token',
        'pending.usageLine': 'What it will do: {text}',
        'pending.tokensLine': 'Tokens to inject: {tokens}',
        'pending.commandLine': 'Command ({lines} lines): ',
        'pending.clickView': 'click to view',
        'pending.expiresIn': '{s}s left',
        'pending.expired': 'expired',
        'pending.title': 'Approvals',
        'approval.subPending': 'Pending',
        'approval.subHistory': 'Decided',
        'history.empty': 'No approval records yet.',
        'history.approved': 'Approved',
        'history.denied': 'Denied',
        'history.timeout': 'Timed out',
        'history.aborted': 'Aborted',
        'history.viaSession': 'session card',
        'history.viaPanel': 'vault panel',
        'history.via': 'Source: {ui}',
        'history.count': '{count} records',
        'history.clear': 'Clear all',
        'history.clearConfirm': 'Confirm clear',
        'history.cleared': 'Approval records cleared.',
        'history.deleted': 'Record deleted.',
        'history.delete': 'Delete',
        'history.needsRestart': 'Approval history needs a dsh web restart to become available.',
        'pending.none': 'Nothing pending.',
        'pending.saveTitle': 'Agent save requests',
        'pending.shTitle': 'vault_sh commands awaiting approval',
        'pending.fromSession': 'From another session',
        'pending.fromSessionNamed': 'From session: {name}',
        'pending.tokenNote': 'The token value is injected only into that command; the session log never sees it.',
        'pending.showCommand': 'Show full command',
        'pending.hideCommand': 'Hide full command',
        'pending.source': 'Requested by the agent',
        'pending.valuePlaceholder': 'Paste the token value here',
        'pending.saved': 'Saved {name} from the agent request.',
        'pending.approved': 'Command approved.',
        'pending.denied': 'Request denied.',
        'security.title': 'Security',
        'security.plain': 'The vault file is plaintext on disk (0600). Set a master password to encrypt it at rest.',
        'security.encryptedUnlocked': 'The vault file is encrypted (scrypt + AES-256-GCM). Lock it when you step away.',
        'security.encryptedLocked': 'The vault is locked. Unlock it to use tokens; agent tools fail until then.',
        'security.masterPassword': 'Master password',
        'security.masterPasswordPlaceholder': 'At least 8 characters',
        'security.encryptAction': 'Encrypt vault',
        'security.changeAction': 'Change master password',
        'security.unlockAction': 'Unlock',
        'security.lockAction': 'Lock now',
        'security.disableAction': 'Disable encryption',
        'security.backupNotice': 'A plaintext backup was left at {path} — delete it once you verified the encrypted vault.',
        'security.backupDelete': 'Delete backup',
        'security.backupDeleted': 'Backup deleted.',
        'security.approval': 'vault_sh commands need my approval',
        'security.approvalUI': '审批方式',
        'security.approvalUISession': '会话内卡片',
        'security.approvalUIPanel': '令牌库面板',
        'security.audit': 'Write the audit log (token-vault-audit.jsonl)',
        'security.lockedHint': 'Unlock the vault to change these settings.',
        'security.notify': 'Desktop notifications',
        'security.sound': 'Sound alerts',
        'security.statePlain': 'Not encrypted',
        'security.stateUnlocked': 'Encrypted',
        'security.stateLocked': 'Locked',
        'lock.title': 'Token vault is locked',
        'lock.checking': 'Loading…',
        'lock.text': 'Enter your master password to see and use the stored tokens.',
        'lock.placeholder': 'Master password',
        'lock.submit': 'Unlock',
        'lock.unlocking': 'Unlocking…',
        'security.changePassword': 'Change password',
        'security.currentPassword': 'Current password',
        'security.newPassword': 'New password',
        'security.applyChange': 'Apply',
        'security.changeHint': 'Enter the current password on the left and the new one here.',
        'security.approvalHint': 'Ask me before any command uses a token',
        'security.approvalUIHint': 'Where the approval appears',
        'security.grantMinutes': 'Approval lasts',
        'security.grantMinutesHint': 'Approved tokens keep working in that session for this long',
        'security.grantOff': 'Ask every command',
        'security.grantMinutesValue': '{minutes} min',
        'security.grantsTitle': 'Active approvals',
        'security.grantNone': 'No active approval.',
        'security.grantRow': '{tokens} · {minutes} min left',
        'security.grantRevoke': 'Revoke',
        'security.grantRevokeAll': 'Revoke all',
        'security.grantRevoked': 'Approval revoked.',
        'security.auditHint': 'Log each use (token names and commands, never values)',
        'security.notifyHint': 'Browser notification when a confirmation is waiting',
        'security.soundHint': 'Short beep when a confirmation arrives',
        'pending.stale': 'This request is no longer pending (it may have timed out or been resolved).',
        'notify.title': 'Token vault needs your confirmation',
        'notify.approval': 'A vault_sh command is waiting for your approval.',
        'notify.save': 'An agent requested saving a token — your input is needed.',
        'transfer.title': 'Import / export',
        'transfer.exportTitle': 'Export',
        'transfer.importTitle': 'Import',
        'transfer.envTitle': 'Import .env',
        'transfer.lead':
          'Export writes every token to a file. With a password the file is encrypted (scrypt + AES-256-GCM); without one it is plain JSON and requires typing EXPORT below.',
        'transfer.exportPassword': 'Export password',
        'transfer.exportPasswordPlaceholder': 'Leave blank to export plain JSON',
        'transfer.exportConfirmPlaceholder': 'Type EXPORT to confirm a plain export',
        'transfer.exportAction': 'Export',
        'transfer.exporting': 'Exporting…',
        'transfer.plainWarning': 'A plain export writes token values into the file — store it carefully.',
        'transfer.pickFile': 'Choose file…',
        'transfer.noFile': 'No file selected',
        'transfer.importPassword': 'File password',
        'transfer.importPasswordPlaceholder': 'Only for an encrypted .tvault file',
        'transfer.mode': 'Existing names',
        'transfer.modeMerge': 'Keep',
        'transfer.modeOverwrite': 'Overwrite',
        'transfer.importAction': 'Import',
        'transfer.importing': 'Importing…',
        'transfer.hint': 'Accepts a plain .json export or an encrypted .tvault file.',
        'transfer.envHint': 'Parses KEY=value lines (comments and blank lines are ignored).',
        'transfer.envPick': 'Choose .env…',
        'transfer.envEntries': '{count} entries found',
        'transfer.envAction': 'Import .env',
        'transfer.exported': 'Exported {count} token(s) to {filename}.',
        'transfer.imported': 'Import finished: {added} added, {updated} updated, {skipped} kept.',
        'transfer.envImported': '.env import finished: {added} added, {updated} updated, {skipped} kept, {rejected} invalid.',
      },
      zh: {
        nav: '令牌库',
        lead:
          '令牌保存在本机文件里，不会出现在会话中：vault_sh 把令牌注入命令的环境变量，命令回显出的令牌也会被自动隐藏。',
        'field.name': '名称',
        'field.namePlaceholder': '例如 GITHUB_TOKEN',
        'field.value': '令牌值',
        'field.valuePlaceholder': '粘贴令牌，保存后不再显示',
        'field.note': '备注',
        'field.notePlaceholder': '这个令牌用来做什么（可选）',
        'field.newValue': '新令牌值',
        'field.keepValue': '留空则保持当前值',
        'field.checkUrl': '检查 URL（可选）',
        'field.checkUrlPlaceholder': '例如 https://api.github.com/user',
        'field.expires': '有效期至（可选）',
        'field.envFile': '从 .env 文件导入',
        'action.save': '保存令牌',
        'action.saving': '保存中…',
        'action.saveChanges': '保存',
        'action.cancel': '取消',
        'action.copyVariable': '复制 $NAME',
        'action.copied': '已复制',
        'action.replace': '替换值',
        'action.rename': '改名',
        'action.check': '测试',
        'action.checking': '测试中…',
        'action.delete': '删除',
        'action.confirmDelete': '确认删除',
        'action.approve': '批准',
        'action.deny': '拒绝',
        'action.enable': '启用',
        'tab.tokens': '令牌',
        'tab.pending': '审批',
        'tab.security': '安全',
        'tab.transfer': '导入导出',
        'list.title': '已保存的令牌',
        'list.count': '共 {count} 个',
        'list.loading': '加载中…',
        'list.empty': '还没有令牌，在上面的表单里添加一个。',
        'list.searchPlaceholder': '按名称或备注筛选…',
        'list.searchEmpty': '没有令牌匹配筛选条件。',
        'row.hidden': '•••••••• · {count} 个字符',
        'row.neverUsed': '从未使用',
        'row.lastUsed': '最后使用 {when}',
        'row.usedBy': '（{who}）',
        'row.expired': '已于 {when} 过期',
        'row.expiresSoon': '{days} 天后到期',
        'row.disabled': '已停用',
        'check.ok': '有效（{status}）',
        'check.unauthorized': '已失效（{status}，多半是令牌过期）',
        'check.other': '状态码 {status}',
        'error.nameRequired': '请填写名称。',
        'error.nameInvalid': '请以字母或下划线开头，只能包含字母、数字、点、横线或下划线。',
        'error.valueRequired': '请填写令牌值。',
        'error.copyFailed': '当前浏览器不允许访问剪贴板。',
        'error.exportConfirm': '明文导出需要在确认框里输入 EXPORT。',
        'notice.saved': '已保存 {name}。',
        'notice.updated': '已更新 {name}。',
        'notice.deleted': '已删除 {name}。',
        'notice.renamed': '已改名为 {name}。',
        'notice.duplicate': '这个值和已有令牌 {names} 相同——建议直接更新那个令牌。',
        'hint.prefix': '识别为 {provider} 令牌，已预填名称；保存后可再设置检查 URL。',
        'pending.cardTitle': '这次调用要用你的令牌',
        'pending.usageLine': '用途：{text}',
        'pending.tokensLine': '将注入令牌：{tokens}',
        'pending.commandLine': '命令（共 {lines} 行）：',
        'pending.clickView': '点击查看',
        'pending.expiresIn': '剩余 {s} 秒',
        'pending.expired': '已超时',
        'pending.title': '审批',
        'approval.subPending': '待审批',
        'approval.subHistory': '已审批',
        'history.empty': '还没有审批记录。',
        'history.approved': '已批准',
        'history.denied': '已拒绝',
        'history.timeout': '已超时',
        'history.aborted': '已中止',
        'history.viaSession': '会话卡片',
        'history.viaPanel': '令牌库面板',
        'history.via': '来源：{ui}',
        'history.count': '共 {count} 条',
        'history.clear': '清空记录',
        'history.clearConfirm': '确认清空',
        'history.cleared': '审批记录已清空。',
        'history.deleted': '已删除该记录。',
        'history.delete': '删除',
        'history.needsRestart': '审批历史需要重启 dsh web 后才可用。',
        'pending.none': '暂无待确认事项。',
        'pending.saveTitle': 'agent 的保存请求',
        'pending.shTitle': '等待批准的 vault_sh 命令',
        'pending.fromSession': '来自其它会话',
        'pending.fromSessionNamed': '来自会话：{name}',
        'pending.tokenNote': '令牌值只注入那条命令，会话记录里不会出现。',
        'pending.showCommand': '查看完整命令',
        'pending.hideCommand': '收起完整命令',
        'pending.source': '由 agent 发起',
        'pending.valuePlaceholder': '在这里粘贴令牌值',
        'pending.saved': '已按 agent 请求保存 {name}。',
        'pending.approved': '已批准该命令。',
        'pending.denied': '已拒绝该请求。',
        'security.title': '安全',
        'security.plain': '库文件目前是本机明文（0600 权限）。设置主密码后可加密落盘。',
        'security.encryptedUnlocked': '库文件已加密（scrypt + AES-256-GCM）。离开时可以点击「立即上锁」。',
        'security.encryptedLocked': '令牌库已上锁。解锁前 agent 工具无法使用令牌。',
        'security.masterPassword': '主密码',
        'security.masterPasswordPlaceholder': '至少 8 个字符',
        'security.encryptAction': '加密令牌库',
        'security.changeAction': '更换主密码',
        'security.unlockAction': '解锁',
        'security.lockAction': '立即上锁',
        'security.disableAction': '关闭加密',
        'security.backupNotice': '加密前留了一份明文备份在 {path}，确认加密库可用后请删除它。',
        'security.backupDelete': '删除备份',
        'security.backupDeleted': '备份已删除。',
        'security.approval': 'vault_sh 命令需要我批准',
        'security.approvalUI': '审批方式',
        'security.approvalUISession': '会话内卡片',
        'security.approvalUIPanel': '令牌库面板',
        'security.audit': '写入审计日志（token-vault-audit.jsonl）',
        'security.lockedHint': '解锁后才能修改这些设置。',
        'security.notify': '桌面通知',
        'security.sound': '提示音',
        'security.statePlain': '未加密',
        'security.stateUnlocked': '已加密',
        'security.stateLocked': '已上锁',
        'lock.title': '令牌库已上锁',
        'lock.checking': '加载中…',
        'lock.text': '输入主密码后才能查看和使用里面的令牌。',
        'lock.placeholder': '主密码',
        'lock.submit': '解锁',
        'lock.unlocking': '解锁中…',
        'security.changePassword': '更换主密码',
        'security.currentPassword': '当前主密码',
        'security.newPassword': '新主密码',
        'security.applyChange': '确认更换',
        'security.changeHint': '左边填当前主密码，右边填新主密码，点「确认更换」。',
        'security.approvalHint': '命令要用令牌之前先问我',
        'security.approvalUIHint': '审批提示出现在哪里',
        'security.grantMinutes': '审批有效期',
        'security.grantMinutesHint': '批准后这些令牌在该会话内可继续使用，不必重复批准',
        'security.grantOff': '每次都要批准',
        'security.grantMinutesValue': '{minutes} 分钟',
        'security.grantsTitle': '有效授权',
        'security.grantNone': '当前没有有效授权。',
        'security.grantRow': '{tokens} · 剩 {minutes} 分钟',
        'security.grantRevoke': '撤销',
        'security.grantRevokeAll': '全部撤销',
        'security.grantRevoked': '已撤销授权。',
        'security.auditHint': '记录每次使用（只记令牌名和命令，不记值）',
        'security.notifyHint': '有待确认事项时弹浏览器通知',
        'security.soundHint': '有待确认事项时响一声',
        'pending.stale': '该请求已失效（可能已超时或在别处处理过）。',
        'notify.title': '令牌库有待确认事项',
        'notify.approval': '一条 vault_sh 命令正在等待你批准。',
        'notify.save': 'agent 请求保存一个令牌，等你填写。',
        'transfer.title': '导入 / 导出',
        'transfer.exportTitle': '导出',
        'transfer.importTitle': '导入',
        'transfer.envTitle': '导入 .env',
        'transfer.lead':
          '导出会把所有令牌写进一个文件；填了密码就用 scrypt + AES-256-GCM 加密，不填就是明文 JSON，且需要在确认框输入 EXPORT。',
        'transfer.exportPassword': '导出密码',
        'transfer.exportPasswordPlaceholder': '留空 = 明文导出',
        'transfer.exportConfirmPlaceholder': '明文导出请输入 EXPORT 确认',
        'transfer.exportAction': '导出',
        'transfer.exporting': '导出中…',
        'transfer.plainWarning': '明文导出会把令牌值写进文件，请妥善保存。',
        'transfer.pickFile': '选择文件…',
        'transfer.noFile': '未选择文件',
        'transfer.importPassword': '文件密码',
        'transfer.importPasswordPlaceholder': '只有加密的 .tvault 文件才需要',
        'transfer.mode': '同名令牌',
        'transfer.modeMerge': '保留现有',
        'transfer.modeOverwrite': '覆盖',
        'transfer.importAction': '导入',
        'transfer.importing': '导入中…',
        'transfer.hint': '支持明文 .json 导出文件或加密的 .tvault 文件。',
        'transfer.envHint': '解析 KEY=value 行（忽略注释和空行）。',
        'transfer.envPick': '选择 .env 文件…',
        'transfer.envEntries': '找到 {count} 条',
        'transfer.envAction': '导入 .env',
        'transfer.exported': '已导出 {count} 个令牌到 {filename}。',
        'transfer.imported': '导入完成：新增 {added}，更新 {updated}，保留 {skipped}。',
        'transfer.envImported': '.env 导入完成：新增 {added}，更新 {updated}，保留 {skipped}，无效 {rejected} 条。',
      },
    }

    const STYLE = `
.tv-section{display:flex;flex-direction:column;gap:16px;width:100%;max-width:760px;color:var(--dsw-alias-label-primary);font-size:15px;line-height:23px}
.tv-tabs{display:flex;gap:2px;padding:3px;border:.5px solid var(--dsw-alias-border-l1);border-radius:10px;background:var(--dsw-alias-bg-layer-1);width:100%;box-sizing:border-box;overflow-x:auto;scrollbar-width:none}
.tv-tabs::-webkit-scrollbar{display:none}
.tv-tab{display:inline-flex;align-items:center;gap:6px;box-sizing:border-box;flex:1 1 auto;justify-content:center;white-space:nowrap;height:30px;padding:0 12px;border:none;border-radius:8px;background:0 0;color:var(--dsw-alias-label-secondary);font:inherit;font-size:14px;line-height:21px;cursor:pointer;transition:background .12s ease,color .12s ease}
.tv-tab:hover{color:var(--dsw-alias-label-primary);background:var(--dsw-alias-interactive-bg-hover,var(--dsw-alias-bg-layer-2))}
.tv-tabActive,.tv-tabActive:hover{background:var(--dsw-alias-brand-primary);color:var(--dsw-alias-label-primary-foreground);font-weight:500;box-shadow:0 1px 3px rgba(0,0,0,.16)}
.tv-tabActive .tv-tabBadge{background:var(--dsw-alias-label-primary-foreground);color:var(--dsw-alias-brand-primary)}
.tv-tabBadge{display:inline-flex;align-items:center;justify-content:center;min-width:16px;height:16px;padding:0 4px;border-radius:999px;background:var(--dsw-alias-state-error-primary);color:#fff;font-size:12px;line-height:1;font-variant-numeric:tabular-nums}
.tv-lead{margin:0;color:var(--dsw-alias-label-tertiary);font-size:13px;line-height:19px}
.tv-form{display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end;padding:14px;border:.5px solid var(--dsw-alias-border-l1);border-radius:12px;background:var(--dsw-alias-bg-layer-1)}
.tv-field{display:flex;flex-direction:column;gap:6px;flex:1 1 170px;min-width:0}
.tv-field>span{color:var(--dsw-alias-label-secondary);font-size:13px;font-weight:500;line-height:19px}
.tv-input{box-sizing:border-box;width:100%;height:32px;padding:0 10px;border:.5px solid var(--dsw-alias-border-l4);border-radius:8px;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);font:inherit;font-size:15px;line-height:23px}
.tv-input::placeholder{color:var(--dsw-alias-label-tertiary)}
.tv-input:focus-visible{outline:2px solid var(--dsw-alias-brand-primary);outline-offset:-1px}
.tv-primary{box-sizing:border-box;height:32px;padding:0 14px;border:none;border-radius:8px;background:var(--dsw-alias-button-primary-fill);color:var(--dsw-alias-label-primary-foreground);font:inherit;font-size:14px;line-height:21px;cursor:pointer;white-space:nowrap}
.tv-primary:disabled{opacity:.55;cursor:default}
.tv-listHead{display:flex;align-items:baseline;gap:8px}
.tv-listTitle{margin:0;font-size:15px;font-weight:500;line-height:23px}
.tv-count{color:var(--dsw-alias-label-tertiary);font-size:13px;line-height:19px;font-variant-numeric:tabular-nums}
.tv-empty{margin:0;color:var(--dsw-alias-label-tertiary);font-size:13px;line-height:19px}
.tv-search{flex:1 1 200px;min-width:0}
.tv-list{display:flex;flex-direction:column;gap:8px;margin:0;padding:0;list-style:none}
.tv-row{display:flex;flex-direction:column;gap:6px;padding:12px 14px;border:.5px solid var(--dsw-alias-settings-card-stroke,var(--dsw-alias-border-l1));border-radius:12px;background:var(--dsw-alias-settings-card-fill,var(--dsw-alias-bg-layer-1))}
.tv-rowDisabled{opacity:.55}
.tv-rowMain{display:flex;flex-wrap:wrap;align-items:center;gap:6px 10px;min-width:0}
.tv-name{flex:none;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:14px;line-height:21px;color:var(--dsw-alias-label-primary);background:var(--dsw-alias-bg-module-platform,transparent);border-radius:6px;padding:1px 6px}
.tv-env{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;line-height:19px;color:var(--dsw-alias-label-secondary);background:var(--dsw-alias-bg-layer-2);border-radius:6px;padding:1px 6px;white-space:nowrap}
.tv-masked{color:var(--dsw-alias-label-tertiary);font-size:13px;line-height:19px;white-space:nowrap}
.tv-badge{color:var(--dsw-alias-state-warning-primary,var(--dsw-alias-label-secondary));font-size:13px;line-height:19px;white-space:nowrap}
.tv-badgeBad{color:var(--dsw-alias-state-error-primary);font-size:13px;line-height:19px;white-space:nowrap}
.tv-when{margin-left:auto;color:var(--dsw-alias-label-tertiary);font-size:13px;line-height:19px;font-variant-numeric:tabular-nums;white-space:nowrap}
.tv-note{margin:0;color:var(--dsw-alias-label-secondary);font-size:13px;line-height:19px;overflow-wrap:anywhere}
.tv-used{margin:0;color:var(--dsw-alias-label-tertiary);font-size:13px;line-height:19px;overflow-wrap:anywhere}
.tv-checkline{margin:0;color:var(--dsw-alias-label-tertiary);font-size:13px;line-height:19px}
.tv-actions{display:flex;flex-wrap:wrap;align-items:center;gap:2px}
.tv-link{box-sizing:border-box;height:28px;padding:0 10px;border:none;border-radius:6px;background:0 0;color:var(--dsw-alias-label-tertiary);font:inherit;font-size:13px;line-height:19px;cursor:pointer}
.tv-link:hover{background:var(--dsw-alias-interactive-bg-hover,var(--dsw-alias-bg-layer-2));color:var(--dsw-alias-label-primary)}
.tv-danger{box-sizing:border-box;height:28px;padding:0 10px;border:none;border-radius:6px;background:0 0;color:var(--dsw-alias-state-error-primary);font:inherit;font-size:13px;line-height:19px;cursor:pointer}
.tv-danger:hover{background:var(--dsw-alias-interactive-bg-hover,var(--dsw-alias-bg-layer-2))}
.tv-toggle{display:flex;align-items:center;gap:6px;color:var(--dsw-alias-label-secondary);font-size:13px;line-height:19px;cursor:pointer}
.tv-toggle input{margin:0;cursor:pointer}
.tv-edit{display:flex;flex-wrap:wrap;align-items:flex-end;gap:10px}
.tv-error{margin:0;color:var(--dsw-alias-state-error-primary);font-size:13px;line-height:19px}
.tv-toasts{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);z-index:2147483000;display:flex;flex-direction:column;align-items:center;gap:8px;width:max-content;max-width:min(420px,calc(100vw - 32px));pointer-events:none}
.tv-toast{pointer-events:auto;display:flex;align-items:flex-start;gap:8px;max-width:100%;padding:10px 14px;border-radius:10px;font-size:13px;line-height:19px;animation:tv-toast-in .16s ease;box-shadow:0 6px 20px rgba(0,0,0,.10)}
.tv-toast-error{border:1px solid var(--dsw-alias-state-error-primary);background:color-mix(in srgb,var(--dsw-alias-state-error-primary) 10%,var(--dsw-alias-bg-base));color:var(--dsw-alias-state-error-primary)}
.tv-toast-success{border:1px solid var(--dsw-alias-state-success-primary);background:color-mix(in srgb,var(--dsw-alias-state-success-primary) 12%,var(--dsw-alias-bg-base));color:var(--dsw-alias-state-success-primary)}
.tv-toast-warn{border:1px solid var(--dsw-alias-state-warning-primary,var(--dsw-alias-label-secondary));background:color-mix(in srgb,var(--dsw-alias-state-warning-primary,var(--dsw-alias-label-secondary)) 12%,var(--dsw-alias-bg-base));color:var(--dsw-alias-state-warning-primary,var(--dsw-alias-label-secondary))}
.tv-toastText{flex:1 1 auto;overflow-wrap:anywhere;min-width:0}
@keyframes tv-toast-in{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.tv-notice{margin:0;color:var(--dsw-alias-state-success-primary);font-size:13px;line-height:19px}
.tv-warn{margin:0;color:var(--dsw-alias-state-warning-primary,var(--dsw-alias-label-secondary));font-size:13px;line-height:19px}
.tv-transfer{display:flex;flex-direction:column;gap:14px;padding-top:16px;border-top:.5px solid var(--dsw-alias-border-l1)}
.tv-security{display:flex;flex-direction:column;gap:10px;padding-top:16px;border-top:.5px solid var(--dsw-alias-border-l1)}
.tv-secCard{display:flex;flex-direction:column;gap:10px;padding:14px;border:.5px solid var(--dsw-alias-border-l1);border-radius:12px;background:var(--dsw-alias-bg-layer-1)}
.tv-secHead{display:flex;align-items:center;gap:8px;min-width:0}
.tv-dot{width:8px;height:8px;border-radius:50%;flex:none;box-shadow:0 0 0 3px color-mix(in srgb,currentColor 18%,transparent)}
.tv-dotOn{background:var(--dsw-alias-state-success-primary);color:var(--dsw-alias-state-success-primary)}
.tv-dotOff{background:var(--dsw-alias-label-tertiary);color:var(--dsw-alias-label-tertiary)}
.tv-dotWarn{background:var(--dsw-alias-state-warning-primary,var(--dsw-alias-label-secondary));color:var(--dsw-alias-state-warning-primary,var(--dsw-alias-label-secondary))}
.tv-secTitle{margin:0;font-size:14px;font-weight:500;line-height:21px}
.tv-secText{margin:0;color:var(--dsw-alias-label-tertiary);font-size:13px;line-height:19px}
.tv-settings{display:flex;flex-direction:column;border:.5px solid var(--dsw-alias-border-l1);border-radius:12px;overflow:hidden;background:var(--dsw-alias-bg-layer-1)}
.tv-setting{display:flex;align-items:center;gap:14px;padding:12px 14px}
.tv-setting+.tv-setting{border-top:.5px solid var(--dsw-alias-border-l1)}
.tv-settingText{display:flex;flex-direction:column;gap:2px;min-width:0;flex:1 1 auto}
.tv-settingLabel{color:var(--dsw-alias-label-primary);font-size:14px;line-height:21px}
.tv-settingHint{color:var(--dsw-alias-label-tertiary);font-size:13px;line-height:19px}
.tv-settingControl{flex:none;display:flex;align-items:center;gap:8px}
.tv-switch{position:relative;display:inline-block;width:36px;height:20px;flex:none;cursor:pointer}
.tv-switch input{position:absolute;inset:0;width:100%;height:100%;margin:0;opacity:0;cursor:pointer;z-index:1}
.tv-switchTrack{position:absolute;inset:0;border-radius:999px;background:var(--dsw-alias-border-l4);transition:background .16s ease}
.tv-switchTrack::after{content:"";position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;background:#fff;transition:transform .16s ease;box-shadow:0 1px 2px rgba(0,0,0,.25)}
.tv-switch input:checked+.tv-switchTrack{background:var(--dsw-alias-brand-primary)}
.tv-switch input:checked+.tv-switchTrack::after{transform:translateX(16px)}
.tv-switch input:focus-visible+.tv-switchTrack{outline:2px solid var(--dsw-alias-brand-primary);outline-offset:2px}
.tv-switch input:disabled+.tv-switchTrack{opacity:.5}
.tv-formRow{display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end}
.tv-backupRow{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.tv-formRow>.tv-field{flex:1 1 180px}
.tv-pwField{flex:0 1 200px;min-width:160px}
.tv-pwField .tv-input{width:100%}
.tv-dangerBtn{color:var(--dsw-alias-state-error-primary);border-color:var(--dsw-alias-state-error-primary)}
.tv-dangerBtn:hover{background:var(--dsw-alias-interactive-bg-hover,var(--dsw-alias-bg-layer-2))}
.tv-details{margin-top:2px}
.tv-detailsSummary{color:var(--dsw-alias-state-error-primary);font-size:13px;line-height:19px;cursor:pointer;width:fit-content}
.tv-details[open] .tv-detailsSummary{margin-bottom:8px}
.tv-pending{display:flex;flex-direction:column;gap:10px;padding-top:16px;border-top:.5px solid var(--dsw-alias-border-l1)}
.tv-pendingCard{position:relative;display:flex;flex-direction:column;gap:10px;padding:14px 110px 14px 14px;border:.5px solid var(--dsw-alias-border-l2);border-radius:12px;background:var(--dsw-alias-bg-layer-1)}
.tv-pendingHead{display:flex;align-items:center;gap:8px;flex-wrap:wrap;min-width:0}
.tv-pendingDot{width:7px;height:7px;border-radius:50%;flex:none;background:var(--dsw-alias-state-warning-primary,var(--dsw-alias-label-secondary));box-shadow:0 0 0 3px color-mix(in srgb,var(--dsw-alias-state-warning-primary,var(--dsw-alias-label-secondary)) 18%,transparent)}
.tv-linkInline{display:inline;padding:0 2px;border:none;background:0 0;color:var(--dsw-alias-brand-primary);font:inherit;font-size:inherit;line-height:inherit;cursor:pointer;text-decoration:underline}
.tv-pendingTitle{color:var(--dsw-alias-label-primary);font-size:14px;font-weight:500;line-height:21px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%}
.tv-pendingText{margin:0;color:var(--dsw-alias-label-secondary);font-size:13px;line-height:19px}
.tv-pendingActions{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding-top:2px}
.tv-pendingActions .tv-primary,.tv-pendingActions .tv-secondary{height:30px;font-size:14px}
.tv-pendingSpacer{flex:1 1 auto}
.tv-countdown{position:absolute;right:16px;top:50%;transform:translateY(-50%);color:var(--dsw-alias-label-tertiary);font-size:13px;line-height:19px;font-variant-numeric:tabular-nums;white-space:nowrap}
.tv-subtabs{display:flex;gap:2px;padding:3px;border:.5px solid var(--dsw-alias-border-l1);border-radius:10px;background:var(--dsw-alias-bg-layer-1);width:fit-content;max-width:100%}
.tv-subtab{display:inline-flex;align-items:center;gap:6px;height:28px;padding:0 14px;border:none;border-radius:8px;background:0 0;color:var(--dsw-alias-label-secondary);font:inherit;font-size:13px;line-height:20px;cursor:pointer;white-space:nowrap}
.tv-subtab:hover{color:var(--dsw-alias-label-primary)}
.tv-subtabActive,.tv-subtabActive:hover{background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);font-weight:500;box-shadow:0 1px 2px rgba(0,0,0,.08)}
.tv-historyCard{display:flex;flex-direction:column;gap:6px;padding:12px 14px;border:.5px solid var(--dsw-alias-border-l1);border-radius:12px;background:var(--dsw-alias-bg-layer-1)}
.tv-historyHead{display:flex;align-items:center;gap:10px;flex-wrap:wrap;min-width:0}
.tv-historyBadge{display:inline-flex;align-items:center;height:20px;padding:0 8px;border-radius:999px;font-size:12px;line-height:1;font-weight:500}
.tv-history-approved{background:color-mix(in srgb,var(--dsw-alias-state-success-primary) 14%,var(--dsw-alias-bg-base));color:var(--dsw-alias-state-success-primary)}
.tv-history-denied{background:color-mix(in srgb,var(--dsw-alias-state-error-primary) 12%,var(--dsw-alias-bg-base));color:var(--dsw-alias-state-error-primary)}
.tv-history-timeout{background:color-mix(in srgb,var(--dsw-alias-state-warning-primary,var(--dsw-alias-label-secondary)) 14%,var(--dsw-alias-bg-base));color:var(--dsw-alias-state-warning-primary,var(--dsw-alias-label-secondary))}
.tv-history-aborted{background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-tertiary)}
.tv-historyWhen{color:var(--dsw-alias-label-tertiary);font-size:12px;line-height:18px;font-variant-numeric:tabular-nums;white-space:nowrap}
.tv-historyToolbar{display:flex;align-items:center;gap:8px;min-width:0}
@media (min-width:720px){.tv-pendingCard{padding-right:150px}.tv-countdown,.tv-countdownOver{font-size:22px;line-height:26px;font-weight:600}}
.tv-countdownOver{position:absolute;right:16px;top:50%;transform:translateY(-50%);color:var(--dsw-alias-state-error-primary);font-size:13px;line-height:19px;font-variant-numeric:tabular-nums;white-space:nowrap}
.tv-code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;line-height:19px;color:var(--dsw-alias-label-secondary);background:var(--dsw-alias-bg-layer-1);border:.5px solid var(--dsw-alias-border-l1);border-radius:6px;padding:6px 8px;overflow-wrap:anywhere;white-space:pre-wrap}
.tv-columns{display:flex;align-items:stretch;gap:20px;min-width:0}
.tv-column{flex:1 1 0;min-width:0;display:flex;flex-direction:column;gap:8px}
.tv-column+.tv-column{border-left:.5px solid var(--dsw-alias-border-l1);padding-left:20px}
.tv-column>.tv-primary{align-self:stretch;justify-content:center}
.tv-columnTitle{color:var(--dsw-alias-label-primary);font-size:14px;font-weight:500;line-height:21px}
.tv-line{display:flex;flex-wrap:wrap;align-items:center;gap:8px;min-width:0}
.tv-inline{color:var(--dsw-alias-label-secondary);font-size:13px;line-height:19px;white-space:nowrap}
.tv-fileName{flex:1 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--dsw-alias-label-tertiary);font-size:13px;line-height:19px}
.tv-secondary{box-sizing:border-box;height:32px;padding:0 14px;border:.5px solid var(--dsw-alias-border-l3);border-radius:8px;background:0 0;color:var(--dsw-alias-label-primary);font:inherit;font-size:14px;line-height:21px;cursor:pointer;white-space:nowrap}
.tv-secondary:hover{background:var(--dsw-alias-interactive-bg-hover,var(--dsw-alias-bg-layer-2))}
.tv-secondary:disabled{opacity:.55;cursor:default}
.tv-select{box-sizing:border-box;height:32px;padding:0 8px;border:.5px solid var(--dsw-alias-border-l4);border-radius:8px;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);font:inherit;font-size:14px;flex:1 1 auto;min-width:0}
.tv-hint{margin:0;color:var(--dsw-alias-label-tertiary);font-size:13px;line-height:19px}
.tv-grants{display:flex;flex-direction:column;gap:6px;padding:2px 0 8px}
.tv-grantsHead{display:flex;align-items:center;justify-content:space-between;gap:8px}
.tv-grantRow{display:flex;align-items:center;justify-content:space-between;gap:8px;color:var(--dsw-alias-label-secondary);font-size:12px;line-height:18px}
.tv-grantText{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
@media (max-width:720px){.tv-columns{flex-direction:column;gap:16px}.tv-column+.tv-column{border-left:none;border-top:.5px solid var(--dsw-alias-border-l1);padding-left:0;padding-top:16px}}
`

    /** The active locale's strings; replaced by `apply`. */
    let t = (key) => key

    /** The Client context; set once by `apply`. */
    let client

    const subscribeLocale = (listener) => client.locale.subscribe(listener)

    const readLocaleRevision = () => client.locale.getSnapshot().revision

    /** Re-render the page when the active locale or its dictionaries change. */
    function useLocaleRevision() {
      return useSyncExternalStore(subscribeLocale, readLocaleRevision)
    }

    /** Save one exported payload as a download; the anchor never enters the DOM. */
    function download(filename, text) {
      const blob = new Blob([text], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = filename === '' ? 'token-vault-export.json' : filename
      anchor.rel = 'noopener'
      anchor.click()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    }

    /** Human-readable message for one failed route call. */
    function messageOf(failure) {
      if (failure instanceof Error && failure.message !== '') return failure.message
      return String(failure)
    }

    /** One JSON route call; a non-2xx answer keeps the Host's own message. */
    async function call(route, body) {
      let serialized
      if (body !== undefined) {
        try {
          serialized = JSON.stringify(body)
        } catch (error) {
          // A DOM node (and its React fiber back-reference) is circular; name the
          // route instead of surfacing V8's "Converting circular structure" stack.
          throw new Error(`请求「${route}」的数据无法序列化：内部错误（${error.message}）`)
        }
      }
      const init =
        body === undefined
          ? { method: 'GET' }
          : { method: 'POST', headers: { 'content-type': 'application/json' }, body: serialized }
      const response = await fetch(route, init)
      let payload = {}
      try {
        payload = await response.json()
      } catch {
        payload = {}
      }
      if (!response.ok) {
        throw new Error(typeof payload?.message === 'string' && payload.message !== '' ? payload.message : `HTTP ${response.status}`)
      }
      return payload
    }

    // ---------------------------------------------------------------------------
    // Pending-confirmation store: polled globally (not only while the panel is
    // open) so approvals and save requests can notify the user anywhere in the
    // GUI — title flash, optional sound, optional desktop notification.
    // ---------------------------------------------------------------------------

    const NOTIFY_PREF_KEY = 'token-vault.notify'
    const SOUND_PREF_KEY = 'token-vault.sound'

    const pendingListeners = new Set()
    let pendingRevision = 0
    let pendingData = { requests: [], approvals: [] }
    let seenApprovalIds = new Set()
    let seenRequestIds = new Set()
    let titleTimer = null
    let titleOriginal = ''
    let titleCount = 0

    function subscribePending(listener) {
      pendingListeners.add(listener)
      return () => pendingListeners.delete(listener)
    }

    function getPendingRevision() {
      return pendingRevision
    }

    function prefEnabled(key) {
      try {
        return localStorage.getItem(key) === '1'
      } catch {
        return false
      }
    }

    /** A short beep through WebAudio; silently skipped when audio is blocked. */
    let audioContext
    function ensureAudio() {
      if (audioContext !== undefined) return audioContext
      try {
        const Ctx = window.AudioContext ?? window.webkitAudioContext
        if (typeof Ctx !== 'function') return undefined
        audioContext = new Ctx()
      } catch {
        return undefined
      }
      return audioContext
    }
    document.addEventListener('pointerdown', () => ensureAudio(), { once: true, capture: true })

    function playBeep() {
      if (!prefEnabled(SOUND_PREF_KEY)) return
      const audio = ensureAudio()
      if (audio === undefined || audio.state !== 'running') return
      try {
        const osc = audio.createOscillator()
        const gain = audio.createGain()
        osc.frequency.value = 880
        gain.gain.value = 0.06
        osc.connect(gain)
        gain.connect(audio.destination)
        osc.start()
        osc.stop(audio.currentTime + 0.18)
      } catch {
        // Best-effort only.
      }
    }

    /** A desktop notification when the user granted permission; click focuses the tab. */
    function showDesktopNotification(body) {
      if (!prefEnabled(NOTIFY_PREF_KEY)) return
      if (typeof Notification === 'undefined' || Notification.permission !== 'granted') return
      try {
        const notification = new Notification(t('notify.title'), { body, tag: 'token-vault-pending' })
        notification.onclick = () => {
          try {
            window.focus()
          } catch {
            // The tab may already be focused.
          }
          notification.close()
        }
      } catch {
        // Notifications can fail in embedded contexts; the title flash still shows.
      }
    }

    /** Flash the tab title while anything is pending; restore it when clear. */
    function updateTitleFlash() {
      const count = pendingData.approvals.length + pendingData.requests.length
      titleCount = count
      if (count > 0) {
        if (titleTimer === null) {
          // Capture the real title once; never capture one of our own flashing
          // texts (a stale flash must not become the "original").
          if (titleOriginal === '') titleOriginal = document.title
          let flip = false
          titleTimer = setInterval(() => {
            flip = !flip
            document.title = flip ? `🔔 (${titleCount}) ${t('notify.title')}` : titleOriginal
          }, 1200)
        }
        return
      }
      if (titleTimer !== null) {
        clearInterval(titleTimer)
        titleTimer = null
      }
      // Restore even when the timer was already gone: a leftover flashing
      // title (or the original captured mid-flash) must not stick.
      if (titleOriginal !== '') {
        document.title = titleOriginal
        titleOriginal = ''
      }
    }

    function notifyNewPending(previous, next) {
      const freshApprovals = next.approvals.filter((entry) => !seenApprovalIds.has(entry.id))
      const freshRequests = next.requests.filter((entry) => !seenRequestIds.has(entry.id))
      seenApprovalIds = new Set(next.approvals.map((entry) => entry.id))
      seenRequestIds = new Set(next.requests.map((entry) => entry.id))
      if (freshApprovals.length === 0 && freshRequests.length === 0) return
      playBeep()
      if (freshApprovals.length > 0) showDesktopNotification(t('notify.approval'))
      if (freshRequests.length > 0) showDesktopNotification(t('notify.save'))
    }

    function setPendingData(next) {
      const previous = pendingData
      pendingData = next
      pendingRevision += 1
      for (const listener of pendingListeners) listener()
      updateTitleFlash()
      notifyNewPending(previous, next)
    }

    // ---------------------------------------------------------------------------
    // Toast feedback: errors, notices and warnings float over the panel instead
    // of pushing the layout around, and disappear on their own.
    // ---------------------------------------------------------------------------

    const TOAST_TIMEOUT = { error: 6000, success: 3200, warn: 5000 }
    const toastListeners = new Set()
    let toastItems = []
    let toastRevision = 0
    let toastSeq = 0

    function subscribeToasts(listener) {
      toastListeners.add(listener)
      return () => toastListeners.delete(listener)
    }

    function getToastRevision() {
      return toastRevision
    }

    function dismissToast(id) {
      const next = toastItems.filter((item) => item.id !== id)
      if (next.length === toastItems.length) return
      toastItems = next
      toastRevision += 1
      for (const listener of toastListeners) listener()
    }

    /** Show one toast; identical text already on screen is refreshed, not doubled. */
    function pushToast(kind, text) {
      if (typeof text !== 'string' || text === '') return
      const existing = toastItems.find((item) => item.kind === kind && item.text === text)
      if (existing !== undefined) return
      const id = `toast-${++toastSeq}`
      toastItems = [...toastItems, { id, kind, text }]
      toastRevision += 1
      for (const listener of toastListeners) listener()
      setTimeout(() => dismissToast(id), TOAST_TIMEOUT[kind] ?? 4000)
    }

    /** The floating stack, rendered by the page shell so it also covers the lock screen. */
    function ToastHost() {
      useSyncExternalStore(subscribeToasts, getToastRevision)
      if (toastItems.length === 0) return null
      return h(
        'div',
        { className: 'tv-toasts', role: 'status', 'aria-live': 'polite' },
        toastItems.map((item) =>
          h(
            'div',
            { key: item.id, className: `tv-toast tv-toast-${item.kind}` },
            h('span', { className: 'tv-toastText' }, item.text),
          ),
        ),
      )
    }

    // ---------------------------------------------------------------------------
    // Vault lock state: shared by the page shell so a locked vault hides the
    // entire panel behind one unlock card instead of merely disabling fields.
    // ---------------------------------------------------------------------------

    let vaultSecurity = { locked: false, encrypted: false }
    const vaultSecurityListeners = new Set()
    let vaultSecurityRevision = 0

    function subscribeVaultSecurity(listener) {
      vaultSecurityListeners.add(listener)
      return () => vaultSecurityListeners.delete(listener)
    }

    function getVaultSecurityRevision() {
      return vaultSecurityRevision
    }

    /** Publish the latest lock state; only a real change re-renders the shell. */
    function publishVaultSecurity(encrypted, locked) {
      if (vaultSecurity.encrypted === encrypted && vaultSecurity.locked === locked) return
      vaultSecurity = { encrypted, locked }
      vaultSecurityRevision += 1
      for (const listener of vaultSecurityListeners) listener()
    }

    /** One pending poll; safe to call from anywhere (panel open or not). */
    async function pollPending() {
      try {
        const payload = await call(PENDING_ROUTE)
        const next = { requests: payload.requests ?? [], approvals: payload.approvals ?? [] }
        const same =
          next.approvals.length === pendingData.approvals.length &&
          next.requests.length === pendingData.requests.length &&
          next.approvals.every((entry, index) => entry.id === pendingData.approvals[index]?.id) &&
          next.requests.every((entry, index) => entry.id === pendingData.requests[index]?.id)
        if (!same) setPendingData(next)
        else updateTitleFlash()
      } catch {
        // The GUI may be restarting; keep polling.
      }
    }

    /** Parse one .env document into candidate entries; comments and blanks are ignored. */
    function parseEnvFile(text) {
      const entries = []
      for (const rawLine of text.split(/\r?\n/)) {
        const line = rawLine.trim()
        if (line === '' || line.startsWith('#')) continue
        const body = line.replace(/^export\s+/, '')
        const eq = body.indexOf('=')
        if (eq <= 0) continue
        const name = body.slice(0, eq).trim()
        let value = body.slice(eq + 1).trim()
        if (value.length >= 2 && ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'")))) {
          value = value.slice(1, -1)
        }
        if (name === '' || value === '') continue
        entries.push({ name, value })
      }
      return entries
    }

    /** Recognise a known token prefix; returns the suggestion or null. */
    function prefixHint(value) {
      for (const [pattern, hint] of PREFIX_HINTS) {
        if (pattern.test(value)) return hint
      }
      return null
    }

    /** A labelled text input. */
    function Field(props) {
      return h(
        'label',
        { className: 'tv-field' },
        h('span', null, props.label),
        h('input', {
          className: 'tv-input',
          type: props.type ?? 'text',
          value: props.value,
          placeholder: props.placeholder,
          autoComplete: props.autoComplete ?? 'off',
          spellCheck: false,
          onChange: props.onChange,
        }),
      )
    }

    /** A pill switch (the setting rows' control). */
    function Switch(props) {
      return h(
        'label',
        { className: 'tv-switch', title: props.hint === undefined ? undefined : props.hint },
        h('input', { type: 'checkbox', checked: props.checked, disabled: props.disabled, onChange: props.onChange }),
        h('span', { className: 'tv-switchTrack' }),
      )
    }

    /** One setting row: label plus hint on the left, its control on the right. */
    function SettingRow(props) {
      return h(
        'div',
        { className: 'tv-setting' },
        h(
          'div',
          { className: 'tv-settingText' },
          h('span', { className: 'tv-settingLabel' }, props.label),
          props.hint === undefined ? null : h('span', { className: 'tv-settingHint' }, props.hint),
        ),
        h('div', { className: 'tv-settingControl' }, props.children),
      )
    }

    /** Format a timestamp for display. */
    function formatWhen(value) {
      if (typeof value !== 'string' || value === '') return ''
      const date = new Date(value)
      if (Number.isNaN(date.getTime())) return ''
      return date.toLocaleString()
    }

    /** The expiry / enabled badges of one row (inline; the last-used line is separate). */
    function RowState(props) {
      const token = props.token
      const parts = []
      if (token.enabled === false) parts.push(h('span', { className: 'tv-badgeBad', key: 'disabled' }, t('row.disabled')))
      if (typeof token.expiresAt === 'string') {
        const days = Math.ceil((new Date(token.expiresAt).getTime() - Date.now()) / 86_400_000)
        if (days < 0) parts.push(h('span', { className: 'tv-badgeBad', key: 'expired' }, t('row.expired', { when: token.expiresAt.slice(0, 10) })))
        else if (days <= 7) parts.push(h('span', { className: 'tv-badge', key: 'soon' }, t('row.expiresSoon', { days })))
      }
      return h('span', { style: { display: 'contents' } }, parts)
    }

    /** One stored token: name, masked length, note, and its value-free actions. */
    function TokenRow(props) {
      const token = props.token
      const editing = props.editing !== null && props.editing.name === token.name
      const renaming = props.renaming !== null && props.renaming.from === token.name
      const pendingDelete = props.pendingDelete === token.name
      const when = formatWhen(token.updatedAt)
      const check = props.checks[token.name]
      const usedText = typeof token.lastUsedAt === 'string'
        ? t('row.lastUsed', { when: formatWhen(token.lastUsedAt) }) + (token.lastUsedBy ? t('row.usedBy', { who: token.lastUsedBy }) : '')
        : t('row.neverUsed')
      return h(
        'li',
        { className: `tv-row${token.enabled === false ? ' tv-rowDisabled' : ''}` },
        h(
          'div',
          { className: 'tv-rowMain' },
          renaming
            ? h('input', {
                className: 'tv-input',
                style: { maxWidth: 240 },
                value: props.renaming.to,
                autoFocus: true,
                spellCheck: false,
                onChange: (event) => props.onRenameValue(event.target.value),
                onKeyDown: (event) => {
                  if (event.key === 'Enter') props.onSubmitRename()
                },
              })
            : h('code', { className: 'tv-name' }, token.name),
          token.env === undefined ? null : h('code', { className: 'tv-env' }, `$${token.env}`),
          h('span', { className: 'tv-masked' }, t('row.hidden', { count: token.length })),
          h(RowState, { token }),
          when === '' ? null : h('span', { className: 'tv-when' }, when),
        ),
        token.note === '' ? null : h('p', { className: 'tv-note' }, token.note),
        h('p', { className: 'tv-used' }, usedText),
        check === undefined ? null : h('p', { className: check.ok === undefined ? 'tv-warn' : check.ok ? 'tv-notice' : 'tv-error' }, check.text),
        renaming
          ? h(
              'div',
              { className: 'tv-actions' },
              h('button', { type: 'button', className: 'tv-primary', disabled: props.busy, onClick: props.onSubmitRename }, t('action.saveChanges')),
              h('button', { type: 'button', className: 'tv-link', onClick: props.onCancelRename }, t('action.cancel')),
            )
          : editing
            ? h(
                'form',
                {
                  className: 'tv-edit',
                  onSubmit: (event) => props.onSubmitEdit(event),
                  autoComplete: 'off',
                },
                h(Field, {
                  label: t('field.newValue'),
                  type: 'password',
                  autoComplete: 'new-password',
                  value: props.editing.value,
                  placeholder: t('field.keepValue'),
                  onChange: (event) => props.onEditValue(event.target.value),
                }),
                h(Field, {
                  label: t('field.note'),
                  value: props.editing.note,
                  placeholder: t('field.notePlaceholder'),
                  onChange: (event) => props.onEditNote(event.target.value),
                }),
                h(Field, {
                  label: t('field.checkUrl'),
                  value: props.editing.checkUrl,
                  placeholder: t('field.checkUrlPlaceholder'),
                  onChange: (event) => props.onEditCheckUrl(event.target.value),
                }),
                h(Field, {
                  label: t('field.expires'),
                  type: 'date',
                  value: props.editing.expires,
                  onChange: (event) => props.onEditExpires(event.target.value),
                }),
                h(
                  'div',
                  { className: 'tv-actions' },
                  h('button', { type: 'submit', className: 'tv-primary', disabled: props.busy }, t('action.saveChanges')),
                  h('button', { type: 'button', className: 'tv-link', onClick: props.onCancelEdit }, t('action.cancel')),
                ),
              )
            : h(
                'div',
                { className: 'tv-actions' },
                h(
                  'label',
                  { className: 'tv-toggle' },
                  h('input', {
                    type: 'checkbox',
                    checked: token.enabled !== false,
                    onChange: () => props.onToggle(token),
                  }),
                  t('action.enable'),
                ),
                h(
                  'button',
                  { type: 'button', className: 'tv-link', onClick: () => props.onCopy(token) },
                  props.copied === token.name ? t('action.copied') : t('action.copyVariable'),
                ),
                h('button', { type: 'button', className: 'tv-link', onClick: () => props.onEdit(token) }, t('action.replace')),
                h('button', { type: 'button', className: 'tv-link', onClick: () => props.onRename(token) }, t('action.rename')),
                h(
                  'button',
                  { type: 'button', className: 'tv-link', disabled: props.busy || props.checking === token.name, onClick: () => props.onCheck(token) },
                  props.checking === token.name ? t('action.checking') : t('action.check'),
                ),
                h(
                  'button',
                  {
                    type: 'button',
                    className: pendingDelete ? 'tv-danger' : 'tv-link',
                    disabled: props.busy,
                    onClick: () => props.onDelete(token.name),
                  },
                  pendingDelete ? t('action.confirmDelete') : t('action.delete'),
                ),
              ),
      )
    }

    /** The Token vault panel (shared by the sidebar page). */
    function TokenSection() {
      useLocaleRevision()
      const [state, setState] = useState(null)
      const tokens = state?.tokens
      const locked = state?.locked === true
      const encrypted = state?.encrypted === true
      const settings = state?.settings ?? { requireApproval: false, audit: true }
      const grants = state?.grants ?? []
      const backupPath = state?.backupPath ?? ''
      // Feedback is floating (toasts); these helpers keep the call sites terse.
      const showError = (text) => { if (text !== '') pushToast('error', String(text)) }
      const showNotice = (text) => { if (text !== '') pushToast('success', String(text)) }
      const [busy, setBusy] = useState(false)
      const [draft, setDraft] = useState({ name: '', value: '', note: '' })
      const [prefixSaid, setPrefixSaid] = useState('')
      const [editing, setEditing] = useState(null)
      const [renaming, setRenaming] = useState(null)
      const [pendingDelete, setPendingDelete] = useState('')
      const [copied, setCopied] = useState('')
      const [search, setSearch] = useState('')
      const [checks, setChecks] = useState({})
      const [checking, setChecking] = useState('')
      // Health results are transient: each one clears itself after 3s.
      const checkTimers = useRef({})
      useEffect(() => () => {
        for (const timer of Object.values(checkTimers.current)) clearTimeout(timer)
      }, [])
      const [pendingValue, setPendingValue] = useState({})
      const [expandedApprovals, setExpandedApprovals] = useState({})
      const [approvalView, setApprovalView] = useState('pending')
      const [history, setHistory] = useState(null)
      const [confirmClear, setConfirmClear] = useState(false)
      const [notifyPref, setNotifyPref] = useState(() => prefEnabled(NOTIFY_PREF_KEY))
      const [soundPref, setSoundPref] = useState(() => prefEnabled(SOUND_PREF_KEY))
      const [security, setSecurity] = useState({ password: '', newPassword: '' })
      const [changingPassword, setChangingPassword] = useState(false)
      const [exportPassword, setExportPassword] = useState('')
      const [exportConfirm, setExportConfirm] = useState('')
      const [importPassword, setImportPassword] = useState('')
      const [importMode, setImportMode] = useState('merge')
      const [importFile, setImportFile] = useState(null)
      const [envImport, setEnvImport] = useState(null)
      const [envMode, setEnvMode] = useState('merge')
      const fileInput = useRef(null)
      const envInput = useRef(null)

      const applyState = (payload) => {
        setState(payload)
        publishVaultSecurity(payload.encrypted === true, payload.locked === true)
      }

      const refresh = useCallback(async () => {
        try {
          applyState(await call(LIST_ROUTE))
        } catch (failure) {
          pushToast('error', messageOf(failure))
          setState((current) => current ?? { tokens: [], locked: false, encrypted: false, settings: { requireApproval: false, audit: true } })
        }
      }, [])

      useEffect(() => {
        refresh()
      }, [refresh])

      useEffect(() => {
        if (copied === '') return undefined
        const timer = setTimeout(() => setCopied(''), 1600)
        return () => clearTimeout(timer)
      }, [copied])

      // Pending confirmations come from the global poller (it runs whether or
      // not this panel is mounted, so notifications work anywhere in the GUI).
      useSyncExternalStore(subscribePending, getPendingRevision)
      const pending = pendingData
      const pendingCount = pending.approvals.length + pending.requests.length
      const [tab, setTab] = useState('tokens')
      const [now, setNow] = useState(() => Date.now())
      useEffect(() => {
        if (pending.approvals.length === 0) return undefined
        const timer = setInterval(() => setNow(Date.now()), 1000)
        return () => clearInterval(timer)
      }, [pending.approvals.length])

      const run = async (operation, { notices } = {}) => {
        if (busy) return undefined
        setBusy(true)
        try {
          const payload = await operation()
          if (notices !== undefined) showNotice(notices(payload))
          await refresh()
          return payload
        } catch (failure) {
          showError(messageOf(failure))
          return undefined
        } finally {
          setBusy(false)
        }
      }

      /** A silent path for toggle-style controls: no global busy churn, so no
        other button (import/export included) dims or flashes when a checkbox
        changes; only the affected data refreshes. */
      const quietRun = async (operation) => {
        try {
          await operation()
          await refresh()
          return true
        } catch (failure) {
          showError(messageOf(failure))
          return false
        }
      }

      const submitDraft = async (event) => {
        event.preventDefault()
        if (busy) return
        const name = draft.name.trim()
        if (name === '') return showError(t('error.nameRequired'))
        if (!NAME_PATTERN.test(name)) return showError(t('error.nameInvalid'))
        if (draft.value === '') return showError(t('error.valueRequired'))
        const payload = await run(() => call(SAVE_ROUTE, { name, value: draft.value, note: draft.note }), {
          notices: () => t('notice.saved', { name }),
        })
        if (payload !== undefined) {
          if (Array.isArray(payload.duplicateOf) && payload.duplicateOf.length > 0) {
            pushToast('warn', t('notice.duplicate', { names: payload.duplicateOf.join('、') }))
          }
          setDraft({ name: '', value: '', note: '' })
          setPrefixSaid('')
        }
      }

      const onDraftValue = (value) => {
        setDraft((current) => {
          const next = { ...current, value }
          const hint = prefixHint(value)
          if (hint !== null && current.name.trim() === '') {
            next.name = hint.name
            if (hint.note !== undefined && current.note === '') next.note = hint.note
            setPrefixSaid(hint.note ?? hint.name)
          }
          return next
        })
      }

      const submitEdit = (event) => {
        event.preventDefault()
        if (busy || editing === null) return
        const body = { name: editing.name, note: editing.note, checkUrl: editing.checkUrl }
        if (editing.value !== '') body.value = editing.value
        body.expiresAt = editing.expires === '' ? null : `${editing.expires}T23:59:59`
        return run(() => call(SAVE_ROUTE, body), { notices: () => t('notice.updated', { name: editing.name }) }).then((payload) => {
          if (payload === undefined) return
          setEditing(null)
          // A replaced value or URL makes any earlier health result stale.
          setChecks((current) => {
            const next = { ...current }
            delete next[editing.name]
            return next
          })
        })
      }

      const remove = (name) => {
        if (pendingDelete !== name) {
          setPendingDelete(name)
          return
        }
        return run(() => call(DELETE_ROUTE, { name }), { notices: () => t('notice.deleted', { name }) }).then(() => {
          setPendingDelete('')
          setChecks((current) => {
            const next = { ...current }
            delete next[name]
            return next
          })
        })
      }

      const rename = () => {
        if (busy || renaming === null) return
        const to = renaming.to.trim()
        if (to === '') return showError(t('error.nameRequired'))
        if (!NAME_PATTERN.test(to)) return showError(t('error.nameInvalid'))
        return run(() => call(RENAME_ROUTE, { from: renaming.from, to }), { notices: () => t('notice.renamed', { name: to }) }).then(() => {
          const previous = renaming.from
          setRenaming(null)
          setChecks((current) => {
            if (current[previous] === undefined) return current
            const next = { ...current, [to]: current[previous] }
            delete next[previous]
            return next
          })
        })
      }

      const toggle = (token) =>
        quietRun(() => call(SAVE_ROUTE, { name: token.name, enabled: token.enabled === false }))

      const scheduleCheckClear = (name) => {
        if (checkTimers.current[name] !== undefined) clearTimeout(checkTimers.current[name])
        checkTimers.current[name] = setTimeout(() => {
          setChecks((current) => {
            if (current[name] === undefined) return current
            const next = { ...current }
            delete next[name]
            return next
          })
        }, 3000)
      }

      const check = async (token) => {
        if (busy) return
        setChecking(token.name)
        try {
          const payload = await call(CHECK_ROUTE, { name: token.name })
          const text = payload.ok
            ? t('check.ok', { status: payload.status })
            : payload.unauthorized
              ? t('check.unauthorized', { status: payload.status })
              : payload.status === 0
                ? t('check.other', { status: payload.status })
                : t('check.other', { status: payload.status })
          setChecks((current) => ({ ...current, [token.name]: { ok: payload.ok, text } }))
          scheduleCheckClear(token.name)
        } catch (failure) {
          setChecks((current) => ({ ...current, [token.name]: { ok: undefined, text: messageOf(failure) } }))
          scheduleCheckClear(token.name)
        } finally {
          setChecking('')
        }
      }

      const copyVariable = async (token) => {
        try {
          await navigator.clipboard.writeText(`$${token.env ?? token.name}`)
          setCopied(token.name)
        } catch {
          showError(t('error.copyFailed'))
        }
      }

      const doExport = async () => {
        if (busy) return
        if (exportPassword === '' && exportConfirm !== EXPORT_CONFIRMATION) {
          showError(t('error.exportConfirm'))
          return
        }
        const payload = await run(() => call(EXPORT_ROUTE, { password: exportPassword, confirm: exportConfirm }), {
          notices: (result) => t('transfer.exported', { count: result.count, filename: result.filename }),
        })
        if (payload !== undefined) download(payload.filename, payload.payload)
      }

      const doImport = () =>
        run(async () => {
          if (importFile === null) throw new Error(t('transfer.noFile'))
          const text = await importFile.text()
          return call(IMPORT_ROUTE, { payload: text, password: importPassword, mode: importMode })
        }, {
          notices: (payload) =>
            t('transfer.imported', { added: payload.added.length, updated: payload.updated.length, skipped: payload.skipped.length }),
        }).then((payload) => {
          if (payload !== undefined) {
            setImportFile(null)
            if (fileInput.current !== null) fileInput.current.value = ''
          }
        })

      const doImportEnv = () =>
        run(async () => {
          if (envImport === null) throw new Error(t('transfer.noFile'))
          const entries = parseEnvFile(envImport.text)
          if (entries.length === 0) throw new Error(t('transfer.envEntries', { count: 0 }))
          return call(IMPORT_ENV_ROUTE, { entries, mode: envMode })
        }, {
          notices: (payload) =>
            t('transfer.envImported', {
              added: payload.added.length,
              updated: payload.updated.length,
              skipped: payload.skipped.length,
              rejected: (payload.rejected ?? []).length,
            }),
        }).then((payload) => {
          if (payload !== undefined) {
            setEnvImport(null)
            if (envInput.current !== null) envInput.current.value = ''
          }
        })

      const loadHistory = async () => {
        try {
          const payload = await call(HISTORY_ROUTE)
          setHistory(Array.isArray(payload.history) ? payload.history : [])
        } catch (failure) {
          const message = messageOf(failure)
          // A 404 here means the running Host predates this route (the page was
          // refreshed with a newer client half but dsh web was not restarted).
          pushToast('warn', /HTTP 404/.test(message) ? t('history.needsRestart') : message)
          setHistory([])
        }
      }

      const deleteHistoryEntry = async (id) => {
        try {
          await call(HISTORY_DELETE_ROUTE, { id })
          await loadHistory()
          pushToast('success', t('history.deleted'))
        } catch (failure) {
          pushToast('error', messageOf(failure))
        }
      }

      const clearHistory = async () => {
        if (!confirmClear) {
          setConfirmClear(true)
          return
        }
        setConfirmClear(false)
        try {
          await call(HISTORY_CLEAR_ROUTE, {})
          await loadHistory()
          pushToast('success', t('history.cleared'))
        } catch (failure) {
          pushToast('error', messageOf(failure))
        }
      }

      const resolvePending = async (id, decision, extra) => {
        setBusy(true)
        try {
          const payload = await call(RESOLVE_ROUTE, { id, decision, ...extra })
          if (payload.saved === true) showNotice(t('pending.saved', { name: payload.token?.name ?? '' }))
          else showNotice(decision === 'approve' ? t('pending.approved') : t('pending.denied'))
          await refresh()
        } catch (failure) {
          const message = messageOf(failure)
          // A card the poller has not removed yet (timed out, aborted call, or
          // already resolved elsewhere) reads as "stale", not as an error.
          if (/找不到这个待确认请求|no pending request with this id/i.test(message)) showNotice(t('pending.stale'))
          else showError(message)
        } finally {
          setBusy(false)
          pollPending()
        }
      }

      const lock = () => run(() => call(LOCK_ROUTE, {}), { notices: () => t('security.encryptedLocked') })

      const encrypt = () => {
        const nextPassword = changingPassword ? security.newPassword : security.password
        return run(() => call(ENCRYPT_ROUTE, { password: nextPassword }), {
          notices: () => t('security.encryptedUnlocked'),
        }).then((payload) => {
          if (payload === undefined) return
          setSecurity({ password: '', newPassword: '' })
          setChangingPassword(false)
        })
      }

      const disableEncryption = () =>
        run(() => call(DISABLE_ENCRYPTION_ROUTE, { password: security.password }), {
          notices: () => t('security.plain'),
        }).then((payload) => {
          if (payload !== undefined) setSecurity({ password: '', newPassword: '' })
        })

      const deleteBackup = () => run(() => call(DELETE_BACKUP_ROUTE, {}), { notices: () => t('security.backupDeleted') })

      const updateSetting = (field, value) =>
        quietRun(() => call(SETTINGS_ROUTE, { [field]: value }))

      const revokeGrant = (session) =>
        run(() => call(REVOKE_GRANT_ROUTE, session === undefined ? {} : { session }), {
          notices: () => t('security.grantRevoked'),
        })

      const filtered = (tokens ?? []).filter((token) => {
        if (search.trim() === '') return true
        const needle = search.trim().toLowerCase()
        return token.name.toLowerCase().includes(needle) || token.note.toLowerCase().includes(needle)
      })

      // Outcomes list: decision, source (session card vs panel), session,
      // tokens and purpose. Command text and values never live here.
      const historyView = (() => {
        if (history === null) return h('p', { className: 'tv-empty' }, t('list.loading'))
        if (history.length === 0) return h('p', { className: 'tv-empty' }, t('history.empty'))
        return h(
          React.Fragment,
          null,
          h('div', { className: 'tv-historyToolbar' },
            h('span', { className: 'tv-count' }, t('history.count', { count: history.length })),
            h('span', { className: 'tv-pendingSpacer' }),
            h('button', {
              type: 'button',
              className: confirmClear ? 'tv-danger' : 'tv-link',
              onClick: clearHistory,
            }, confirmClear ? t('history.clearConfirm') : t('history.clear')),
          ),
          h('ul', { className: 'tv-list' }, history.map((entry) =>
            h('li', { key: entry.id, className: 'tv-historyCard' },
              h('div', { className: 'tv-historyHead' },
                h('span', { className: `tv-historyBadge tv-history-${entry.decision}` }, t(`history.${entry.decision}`)),
                h('span', { className: 'tv-historyWhen' }, formatWhen(entry.at)),
                h('span', { className: 'tv-inline' }, t('history.via', { ui: entry.ui === 'session' ? t('history.viaSession') : t('history.viaPanel') })),
                entry.sessionTitle === undefined ? null : h('span', { className: 'tv-inline' }, t('pending.fromSessionNamed', { name: entry.sessionTitle })),
                h('span', { className: 'tv-pendingSpacer' }),
                h('button', {
                  type: 'button',
                  className: 'tv-link',
                  onClick: () => deleteHistoryEntry(entry.id),
                }, t('history.delete')),
              ),
              entry.description === '' ? null : h('p', { className: 'tv-note' }, entry.description),
              (entry.tokens ?? []).length === 0 ? null : h('p', { className: 'tv-hint' }, `$ ${(entry.tokens ?? []).join('、')}`),
            ),
          )),
        )
      })()

      return h(
        'div',
        { className: 'tv-section' },
        h('style', { key: 'style' }, STYLE),
        h(
          'div',
          { className: 'tv-tabs', role: 'tablist' },
          TABS.map((entry) =>
            h(
              'button',
              {
                key: entry.key,
                type: 'button',
                role: 'tab',
                'aria-selected': tab === entry.key,
                className: `tv-tab${tab === entry.key ? ' tv-tabActive' : ''}`,
                onClick: () => setTab(entry.key),
              },
              t(entry.label),
              entry.key === 'pending' && pendingCount > 0
                ? h('span', { className: 'tv-tabBadge' }, String(pendingCount))
                : null,
            ),
          ),
        ),
        ...(tab === 'tokens' ? [
        h('p', { className: 'tv-lead' }, t('lead'))] : []),
        ...(tab === 'tokens' ? [
        h(
          'form',
          { className: 'tv-form', onSubmit: submitDraft, autoComplete: 'off' },
          h(Field, {
            label: t('field.name'),
            value: draft.name,
            placeholder: t('field.namePlaceholder'),
            onChange: (event) => setDraft((current) => ({ ...current, name: event.target.value })),
          }),
          h(Field, {
            label: t('field.value'),
            type: 'password',
            autoComplete: 'new-password',
            value: draft.value,
            placeholder: t('field.valuePlaceholder'),
            onChange: (event) => onDraftValue(event.target.value),
          }),
          h(Field, {
            label: t('field.note'),
            value: draft.note,
            placeholder: t('field.notePlaceholder'),
            onChange: (event) => setDraft((current) => ({ ...current, note: event.target.value })),
          }),
          h('button', { type: 'submit', className: 'tv-primary', disabled: busy || locked }, busy ? t('action.saving') : t('action.save')),
          prefixSaid === '' ? null : h('p', { className: 'tv-hint', style: { flexBasis: '100%' } }, t('hint.prefix', { provider: prefixSaid })),
        )] : []),
        ...(tab === 'tokens' ? [
        h(
          'div',
          { className: 'tv-listHead' },
          h('h3', { className: 'tv-listTitle' }, t('list.title')),
          tokens === undefined ? null : h('span', { className: 'tv-count' }, t('list.count', { count: filtered.length })),
          h('div', { className: 'tv-search' },
            h('input', {
              className: 'tv-input',
              value: search,
              placeholder: t('list.searchPlaceholder'),
              onChange: (event) => setSearch(event.target.value),
            })),
        )] : []),
        ...(tab === 'tokens' ? [
        tokens === undefined
          ? h('p', { className: 'tv-empty' }, t('list.loading'))
          : filtered.length === 0
            ? h('p', { className: 'tv-empty' }, search.trim() === '' ? t('list.empty') : t('list.searchEmpty'))
            : h(
                'ul',
                { className: 'tv-list' },
                filtered.map((token) =>
                  h(TokenRow, {
                    key: token.name,
                    token,
                    editing,
                    renaming,
                    pendingDelete,
                    copied,
                    busy,
                    checks,
                    checking,
                    onCopy: copyVariable,
                    onEdit: (target) => {
                      setPendingDelete('')
                      setRenaming(null)
                      setEditing({
                        name: target.name,
                        value: '',
                        note: target.note,
                        checkUrl: target.checkUrl ?? '',
                        expires: typeof target.expiresAt === 'string' ? target.expiresAt.slice(0, 10) : '',
                      })
                    },
                    onEditValue: (value) => setEditing((current) => (current === null ? current : { ...current, value })),
                    onEditNote: (value) => setEditing((current) => (current === null ? current : { ...current, note: value })),
                    onEditCheckUrl: (value) => setEditing((current) => (current === null ? current : { ...current, checkUrl: value })),
                    onEditExpires: (value) => setEditing((current) => (current === null ? current : { ...current, expires: value })),
                    onCancelEdit: () => setEditing(null),
                    onSubmitEdit: submitEdit,
                    onRename: (target) => {
                      setPendingDelete('')
                      setEditing(null)
                      setRenaming({ from: target.name, to: target.name })
                    },
                    onRenameValue: (value) => setRenaming((current) => (current === null ? current : { ...current, to: value })),
                    onCancelRename: () => setRenaming(null),
                    onSubmitRename: rename,
                    onToggle: toggle,
                    onCheck: check,
                    onDelete: remove,
                  }),
                ),
              )] : []),
        ...(tab === 'pending' ? [
        h(
          'div',
          { className: 'tv-pending' },
          h('h3', { className: 'tv-listTitle' }, t('pending.title')),
          h(
            'div',
            { className: 'tv-subtabs', role: 'tablist' },
            h('button', {
              type: 'button',
              role: 'tab',
              className: `tv-subtab${approvalView === 'pending' ? ' tv-subtabActive' : ''}`,
              onClick: () => setApprovalView('pending'),
            }, t('approval.subPending'), pendingCount > 0 ? h('span', { className: 'tv-tabBadge' }, String(pendingCount)) : null),
            h('button', {
              type: 'button',
              role: 'tab',
              className: `tv-subtab${approvalView === 'history' ? ' tv-subtabActive' : ''}`,
              onClick: () => { setApprovalView('history'); loadHistory() },
            }, t('approval.subHistory')),
          ),
          approvalView === 'pending' ? h(React.Fragment, null,
          pending.requests.length === 0 && pending.approvals.length === 0
            ? h('p', { className: 'tv-empty' }, t('pending.none'))
            : null,
          pending.requests.length === 0
            ? null
            : h(
                'div',
                { style: { display: 'flex', flexDirection: 'column', gap: 8 } },
                h('p', { className: 'tv-inline' }, t('pending.saveTitle')),
                pending.requests.map((request) =>
                  h(
                    'form',
                    {
                      key: request.id,
                      className: 'tv-pendingCard',
                      onSubmit: (event) => {
                        event.preventDefault()
                        const value = pendingValue[request.id] ?? ''
                        if (value !== '') resolvePending(request.id, 'approve', { value, note: request.note })
                      },
                      autoComplete: 'off',
                    },
                    h('code', { className: 'tv-name' }, request.name),
                    request.note === '' ? null : h('p', { className: 'tv-note' }, request.note),
                    request.sessionTitle === undefined
                      ? null
                      : h('p', { className: 'tv-hint' }, t('pending.fromSessionNamed', { name: request.sessionTitle })),
                    request.source === '' ? null : h('p', { className: 'tv-hint' }, `${t('pending.source')}: ${request.source}`),
                    h('input', {
                      className: 'tv-input',
                      type: 'password',
                      autoComplete: 'new-password',
                      value: pendingValue[request.id] ?? '',
                      placeholder: t('pending.valuePlaceholder'),
                      onChange: (event) => setPendingValue((current) => ({ ...current, [request.id]: event.target.value })),
                    }),
                    h(
                      'div',
                      { className: 'tv-actions' },
                      h('button', { type: 'submit', className: 'tv-primary', disabled: busy || (pendingValue[request.id] ?? '') === '' }, t('action.saveChanges')),
                      h('button', { type: 'button', className: 'tv-link', disabled: busy, onClick: () => resolvePending(request.id, 'deny') }, t('action.deny')),
                    ),
                  ),
                ),
              ),
          pending.approvals.length === 0
            ? null
            : h(
                'div',
                { style: { display: 'flex', flexDirection: 'column', gap: 8 } },
                h('p', { className: 'tv-inline' }, t('pending.shTitle')),
                pending.approvals.map((approval) => {
                  const expanded = expandedApprovals[approval.id] === true
                  const tokens = approval.tokens ?? []
                  const lines = typeof approval.command === 'string' && approval.command !== '' ? approval.command.split('\n').length : 0
                  return h(
                    'div',
                    { key: approval.id, className: 'tv-pendingCard' },
                    (() => {
                      // The Host sends expiresAt (1.7.7+); against an older Host fall
                      // back to requestedAt + the same 120s the approval queue uses.
                      const expiresAt = typeof approval.expiresAt === 'string'
                        ? new Date(approval.expiresAt).getTime()
                        : typeof approval.requestedAt === 'string'
                          ? new Date(approval.requestedAt).getTime() + APPROVAL_TIMEOUT_MS
                          : Number.NaN
                      const remaining = Number.isNaN(expiresAt) ? undefined : Math.max(0, Math.ceil((expiresAt - now) / 1000))
                      return remaining === undefined
                        ? null
                        : h(
                            'span',
                            { className: remaining <= 0 ? 'tv-countdownOver' : 'tv-countdown' },
                            remaining > 0 ? t('pending.expiresIn', { s: remaining }) : t('pending.expired'),
                          )
                    })(),
                    h(
                      'div',
                      { className: 'tv-pendingHead' },
                      h('span', { className: 'tv-pendingDot' }),
                      h('span', { className: 'tv-pendingTitle' }, t('pending.cardTitle')),
                    ),
                    approval.sessionTitle === undefined
                      ? null
                      : h('p', { className: 'tv-pendingText' }, t('pending.fromSessionNamed', { name: approval.sessionTitle })),
                    approval.description === ''
                      ? null
                      : h('p', { className: 'tv-pendingText' }, t('pending.usageLine', { text: approval.description })),
                    tokens.length === 0
                      ? null
                      : h('p', { className: 'tv-pendingText' }, t('pending.tokensLine', {
                          tokens: (approval.tokenEnvs ?? tokens).map((name) => `$${name}`).join('、'),
                        })),
                    h(
                      'p',
                      { className: 'tv-pendingText' },
                      t('pending.commandLine', { lines }),
                      h('button', {
                        type: 'button',
                        className: 'tv-linkInline',
                        onClick: () => setExpandedApprovals((current) => ({ ...current, [approval.id]: !expanded })),
                      }, expanded ? t('pending.hideCommand') : t('pending.clickView')),
                    ),
                    h('p', { className: 'tv-hint' }, t('pending.tokenNote')),
                    expanded ? h('code', { className: 'tv-code' }, approval.command) : null,
                    h(
                      'div',
                      { className: 'tv-pendingActions' },
                      h('button', { type: 'button', className: 'tv-primary', disabled: busy, onClick: () => resolvePending(approval.id, 'approve') }, t('action.approve')),
                      h('button', { type: 'button', className: 'tv-secondary', disabled: busy, onClick: () => resolvePending(approval.id, 'deny') }, t('action.deny')),
                    ),
                  )
                }),
              ),
          ) : historyView,
        )] : []),
        ...(tab === 'security' ? [
        h(
          'div',
          { className: 'tv-security' },
          h('h3', { className: 'tv-listTitle' }, t('security.title')),

          // Status card: one glance tells whether values are protected on disk.
          h(
            'div',
            { className: 'tv-secCard' },
            h(
              'div',
              { className: 'tv-secHead' },
              h('span', { className: `tv-dot ${encrypted ? (locked ? 'tv-dotWarn' : 'tv-dotOn') : 'tv-dotOff'}` }),
              h('h4', { className: 'tv-secTitle' }, encrypted ? (locked ? t('security.stateLocked') : t('security.stateUnlocked')) : t('security.statePlain')),
            ),
            h('p', { className: 'tv-secText' }, encrypted ? (locked ? t('security.encryptedLocked') : t('security.encryptedUnlocked')) : t('security.plain')),
            locked
              ? null
              : h(
                  'form',
                  { className: 'tv-formRow', onSubmit: (event) => { event.preventDefault(); encrypt() }, autoComplete: 'off' },
                  h('div', { className: 'tv-pwField' },
                    h(Field, {
                      label: encrypted ? t('security.currentPassword') : t('security.masterPassword'),
                      type: 'password',
                      autoComplete: 'new-password',
                      value: security.password,
                      placeholder: t('security.masterPasswordPlaceholder'),
                      onChange: (event) => setSecurity((current) => ({ ...current, password: event.target.value })),
                    })),
                  changingPassword && encrypted
                    ? h('div', { className: 'tv-pwField' },
                        h(Field, {
                          label: t('security.newPassword'),
                          type: 'password',
                          autoComplete: 'new-password',
                          value: security.newPassword,
                          placeholder: t('security.masterPasswordPlaceholder'),
                          onChange: (event) => setSecurity((current) => ({ ...current, newPassword: event.target.value })),
                        }))
                    : null,
                  changingPassword && encrypted
                    ? h(React.Fragment, null,
                        h('button', { type: 'submit', className: 'tv-primary', disabled: busy || security.newPassword === '' }, t('security.applyChange')),
                        h('button', { type: 'button', className: 'tv-secondary', disabled: busy, onClick: () => { setChangingPassword(false); setSecurity((current) => ({ ...current, newPassword: '' })) } }, t('action.cancel')),
                      )
                    : h(React.Fragment, null,
                        encrypted
                          ? h('button', { type: 'button', className: 'tv-primary', disabled: busy || security.password === '', onClick: () => setChangingPassword(true) }, t('security.changePassword'))
                          : h('button', { type: 'submit', className: 'tv-primary', disabled: busy || security.password === '' }, t('security.encryptAction')),
                        encrypted
                          ? h('button', { type: 'button', className: 'tv-secondary', disabled: busy, onClick: lock }, t('security.lockAction'))
                          : null,
                        encrypted
                          ? h('button', { type: 'button', className: 'tv-secondary tv-dangerBtn', disabled: busy || security.password === '', onClick: () => { disableEncryption() } }, t('security.disableAction'))
                          : null,
                      ),
                  encrypted && changingPassword
                    ? h('p', { className: 'tv-hint', style: { flexBasis: '100%' } }, t('security.changeHint'))
                    : null,
                ),
            encrypted && backupPath !== ''
              ? h(
                  'div',
                  { className: 'tv-backupRow' },
                  h('p', { className: 'tv-hint' }, t('security.backupNotice', { path: backupPath })),
                  h(
                    'button',
                    { type: 'button', className: 'tv-secondary', disabled: busy, onClick: deleteBackup },
                    t('security.backupDelete'),
                  ),
                )
              : null,
          ),

          // Settings list: one row per switch, label plus a plain-language hint.
          h(
            'div',
            { className: 'tv-settings' },
            h(SettingRow, {
              label: t('security.approval'),
              hint: t('security.approvalHint'),
            }, h(Switch, {
              checked: settings.requireApproval === true,
              disabled: locked,
              onChange: (event) => updateSetting('requireApproval', event.target.checked),
            })),
            settings.requireApproval === true && !locked
              ? h(SettingRow, {
                  label: t('security.approvalUI'),
                  hint: t('security.approvalUIHint'),
                }, h(
                  'select',
                  {
                    className: 'tv-select',
                    style: { width: 132 },
                    'aria-label': t('security.approvalUI'),
                    value: settings.approvalUI ?? 'session',
                    onChange: (event) => updateSetting('approvalUI', event.target.value),
                  },
                  h('option', { value: 'session' }, t('security.approvalUISession')),
                  h('option', { value: 'panel' }, t('security.approvalUIPanel')),
                ))
              : null,
            settings.requireApproval === true && !locked
              ? h(SettingRow, {
                  label: t('security.grantMinutes'),
                  hint: t('security.grantMinutesHint'),
                }, h(
                  'select',
                  {
                    className: 'tv-select',
                    style: { width: 132 },
                    'aria-label': t('security.grantMinutes'),
                    value: String(settings.approvalGrantMinutes ?? 10),
                    onChange: (event) => updateSetting('approvalGrantMinutes', Number(event.target.value)),
                  },
                  [0, 1, 5, 10, 30, 60].map((minutes) =>
                    h('option', { key: minutes, value: String(minutes) },
                      minutes === 0 ? t('security.grantOff') : t('security.grantMinutesValue', { minutes })),
                  ),
                ))
              : null,
            settings.requireApproval === true && !locked
              ? h('div', { className: 'tv-grants' },
                  h('div', { className: 'tv-grantsHead' },
                    h('span', { className: 'tv-settingLabel' }, t('security.grantsTitle')),
                    grants.length === 0 ? null : h('button', {
                      type: 'button',
                      className: 'tv-link',
                      disabled: busy,
                      onClick: () => revokeGrant(undefined),
                    }, t('security.grantRevokeAll')),
                  ),
                  grants.length === 0
                    ? h('p', { className: 'tv-hint' }, t('security.grantNone'))
                    : grants.map((grant) =>
                        h('div', { key: grant.session, className: 'tv-grantRow' },
                          h('span', { className: 'tv-grantText' },
                            t('security.grantRow', {
                              tokens: grant.tokens.join('、'),
                              minutes: Math.max(1, Math.ceil((grant.remainingMs ?? 0) / 60000)),
                            })),
                          h('button', {
                            type: 'button',
                            className: 'tv-link',
                            disabled: busy,
                            onClick: () => revokeGrant(grant.session),
                          }, t('security.grantRevoke')),
                        ),
                      ),
                )
              : null,
            h(SettingRow, {
              label: t('security.audit'),
              hint: t('security.auditHint'),
            }, h(Switch, {
              checked: settings.audit === true,
              disabled: locked,
              onChange: (event) => updateSetting('audit', event.target.checked),
            })),
            h(SettingRow, {
              label: t('security.notify'),
              hint: t('security.notifyHint'),
            }, h(Switch, {
              checked: notifyPref,
              onChange: (event) => {
                const enabled = event.target.checked
                if (enabled && typeof Notification !== 'undefined' && Notification.permission !== 'granted') {
                  Notification.requestPermission().then((result) => {
                    const granted = result === 'granted'
                    try {
                      localStorage.setItem(NOTIFY_PREF_KEY, granted ? '1' : '0')
                    } catch {
                      // Private modes may refuse; the pref stays session-only.
                    }
                    setNotifyPref(granted)
                  })
                  return
                }
                try {
                  localStorage.setItem(NOTIFY_PREF_KEY, enabled ? '1' : '0')
                } catch {
                  // Ignore.
                }
                setNotifyPref(enabled)
              },
            })),
            h(SettingRow, {
              label: t('security.sound'),
              hint: t('security.soundHint'),
            }, h(Switch, {
              checked: soundPref,
              onChange: (event) => {
                const enabled = event.target.checked
                try {
                  localStorage.setItem(SOUND_PREF_KEY, enabled ? '1' : '0')
                } catch {
                  // Ignore.
                }
                setSoundPref(enabled)
                if (enabled) playBeep()
              },
            })),
          ),
          locked ? h('p', { className: 'tv-hint' }, t('security.lockedHint')) : null,
        )] : []),
        ...(tab === 'transfer' ? [
        h(
          'div',
          { className: 'tv-transfer' },
          h('h3', { className: 'tv-listTitle' }, t('transfer.title')),
          h('p', { className: 'tv-lead' }, t('transfer.lead')),
          h(
            'div',
            { className: 'tv-columns' },
            h(
              'div',
              { className: 'tv-column' },
              h('div', { className: 'tv-columnTitle' }, t('transfer.exportTitle')),
              h('input', {
                className: 'tv-input',
                type: 'password',
                autoComplete: 'new-password',
                'aria-label': t('transfer.exportPassword'),
                value: exportPassword,
                placeholder: t('transfer.exportPasswordPlaceholder'),
                onChange: (event) => setExportPassword(event.target.value),
              }),
              h('input', {
                className: 'tv-input',
                'aria-label': t('transfer.exportConfirmPlaceholder'),
                value: exportConfirm,
                placeholder: t('transfer.exportConfirmPlaceholder'),
                spellCheck: false,
                onChange: (event) => setExportConfirm(event.target.value),
              }),
              h('button', { type: 'button', className: 'tv-primary', disabled: busy || locked, onClick: doExport }, busy ? t('transfer.exporting') : t('transfer.exportAction')),
              h('p', { className: 'tv-hint' }, t('transfer.plainWarning')),
            ),
            h(
              'div',
              { className: 'tv-column' },
              h('div', { className: 'tv-columnTitle' }, t('transfer.importTitle')),
              h(
                'div',
                { className: 'tv-line' },
                h('input', {
                  ref: fileInput,
                  type: 'file',
                  accept: '.json,.tvault,application/json',
                  style: { display: 'none' },
                  onChange: (event) => {
                    const picked = event.target.files && event.target.files[0] ? event.target.files[0] : null
                    setImportFile(picked)
                    setTransfer(null)
                  },
                }),
                h(
                  'button',
                  {
                    type: 'button',
                    className: 'tv-secondary',
                    disabled: busy,
                    onClick: () => {
                      if (fileInput.current !== null) fileInput.current.click()
                    },
                  },
                  t('transfer.pickFile'),
                ),
                h('span', { className: 'tv-fileName' }, importFile === null ? t('transfer.noFile') : importFile.name),
              ),
              h('input', {
                className: 'tv-input',
                type: 'password',
                autoComplete: 'new-password',
                'aria-label': t('transfer.importPassword'),
                value: importPassword,
                placeholder: t('transfer.importPasswordPlaceholder'),
                onChange: (event) => setImportPassword(event.target.value),
              }),
              h(
                'div',
                { className: 'tv-line' },
                h('span', { className: 'tv-inline' }, t('transfer.mode')),
                h(
                  'select',
                  { className: 'tv-select', 'aria-label': t('transfer.mode'), value: importMode, onChange: (event) => setImportMode(event.target.value) },
                  h('option', { value: 'merge' }, t('transfer.modeMerge')),
                  h('option', { value: 'overwrite' }, t('transfer.modeOverwrite')),
                ),
                h('button', { type: 'button', className: 'tv-primary', disabled: busy || importFile === null, onClick: doImport }, busy ? t('transfer.importing') : t('transfer.importAction')),
              ),
              h('p', { className: 'tv-hint' }, t('transfer.hint')),
            ),
          ),
          h(
            'div',
            { className: 'tv-column', style: { borderTop: '.5px solid var(--dsw-alias-border-l1)', paddingTop: 12 } },
            h('div', { className: 'tv-columnTitle' }, t('transfer.envTitle')),
            h(
              'div',
              { className: 'tv-line' },
              h('input', {
                ref: envInput,
                type: 'file',
                accept: '.env,.txt,text/plain',
                style: { display: 'none' },
                onChange: (event) => {
                  const picked = event.target.files && event.target.files[0] ? event.target.files[0] : null
                  if (picked === null) {
                    setEnvImport(null)
                    return
                  }
                  picked.text().then((text) => setEnvImport({ name: picked.name, text, count: parseEnvFile(text).length }))
                },
              }),
              h(
                'button',
                {
                  type: 'button',
                  className: 'tv-secondary',
                  disabled: busy,
                  onClick: () => {
                    if (envInput.current !== null) envInput.current.click()
                  },
                },
                t('transfer.envPick'),
              ),
              h('span', { className: 'tv-fileName' }, envImport === null ? t('transfer.noFile') : envImport.name),
              envImport === null ? null : h('span', { className: 'tv-count' }, t('transfer.envEntries', { count: envImport.count })),
            ),
            h(
              'div',
              { className: 'tv-line' },
              h('span', { className: 'tv-inline' }, t('transfer.mode')),
              h(
                'select',
                { className: 'tv-select', 'aria-label': t('transfer.mode'), value: envMode, onChange: (event) => setEnvMode(event.target.value) },
                h('option', { value: 'merge' }, t('transfer.modeMerge')),
                h('option', { value: 'overwrite' }, t('transfer.modeOverwrite')),
              ),
              h('button', { type: 'button', className: 'tv-primary', disabled: busy || envImport === null, onClick: doImportEnv }, busy ? t('transfer.importing') : t('transfer.envAction')),
            ),
            h('p', { className: 'tv-hint' }, t('transfer.envHint')),
          ),
        )] : []),
      )
    }

    /** The panel's tabs: one category per tab keeps the page short. */
    const TABS = [
      { key: 'tokens', label: 'tab.tokens' },
      { key: 'pending', label: 'tab.pending' },
      { key: 'security', label: 'tab.security' },
      { key: 'transfer', label: 'tab.transfer' },
    ]

    const PAGE_ID = 'token-vault'

    const PAGE_STYLE =
      '.tv-page{display:flex;flex-direction:column;width:100%;height:100%;min-height:0;overflow:auto;scrollbar-gutter:stable;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary)}' +
      '.tv-page-inner{box-sizing:border-box;width:100%;max-width:820px;margin:0 auto;padding:26px clamp(20px,4vw,40px) 48px}' +
      '.tv-lock{box-sizing:border-box;display:flex;align-items:center;justify-content:center;width:100%;height:100%;min-height:100%;padding:40px 24px;background:#fff;color:#1a1a1a}' +
      '.tv-lockCard{box-sizing:border-box;display:flex;flex-direction:column;align-items:center;gap:14px;width:100%;max-width:340px;text-align:center}' +
      '.tv-lockIcon{display:flex;align-items:center;justify-content:center;width:56px;height:56px;border-radius:50%;background:#f2f4f7;color:#5a6472}' +
      '.tv-lockTitle{margin:0;font-size:20px;font-weight:600;line-height:28px;color:#1a1a1a}' +
      '.tv-lockText{margin:0;font-size:14px;line-height:22px;color:#6b7280}' +
      '.tv-lockForm{display:flex;flex-direction:column;gap:10px;width:100%;margin-top:2px}' +
      '.tv-lockInput{box-sizing:border-box;width:100%;height:40px;padding:0 12px;border:1px solid #d6dae1;border-radius:10px;background:#fff;color:#1a1a1a;font:inherit;font-size:15px;text-align:center}' +
      '.tv-lockInput::placeholder{color:#9aa3af}' +
      '.tv-lockInput:focus-visible{outline:2px solid #2f6feb;outline-offset:-1px;border-color:#2f6feb}' +
      '.tv-lockButton{box-sizing:border-box;height:40px;border:none;border-radius:10px;background:#2f6feb;color:#fff;font:inherit;font-size:15px;font-weight:500;cursor:pointer}' +
      '.tv-lockButton:disabled{opacity:.5;cursor:default}\n'

    /** The lock screen: the whole page is this card while the vault is locked. */
    function VaultLockScreen() {
      useLocaleRevision()
      const [password, setPassword] = useState('')
      const [busy, setBusy] = useState(false)

      const submit = async (event) => {
        event.preventDefault()
        if (busy || password === '') return
        setBusy(true)
        try {
          const payload = await call(UNLOCK_ROUTE, { password })
          publishVaultSecurity(payload.encrypted === true, payload.locked === true)
          setPassword('')
        } catch (failure) {
          pushToast('error', messageOf(failure))
        } finally {
          setBusy(false)
        }
      }

      return h(
        'div',
        { className: 'tv-lock' },
        h('style', { key: 'page-style' }, PAGE_STYLE),
        h(
          'div',
          { className: 'tv-lockCard' },
          h(
            'div',
            { className: 'tv-lockIcon' },
            h(
              'svg',
              { width: 26, height: 26, viewBox: '0 0 24 24', fill: 'none', 'aria-hidden': true },
              h('rect', { x: 4.5, y: 10.5, width: 15, height: 10, rx: 2.4, stroke: 'currentColor', strokeWidth: 1.7 }),
              h('path', { d: 'M8 10.5V7.8a4 4 0 0 1 8 0v2.7', stroke: 'currentColor', strokeWidth: 1.7, strokeLinecap: 'round' }),
              h('circle', { cx: 12, cy: 15.4, r: 1.5, fill: 'currentColor' }),
            ),
          ),
          h('h2', { className: 'tv-lockTitle' }, t('lock.title')),
          h('p', { className: 'tv-lockText' }, t('lock.text')),
          h(
            'form',
            { className: 'tv-lockForm', onSubmit: submit, autoComplete: 'off' },
            h('input', {
              className: 'tv-lockInput',
              type: 'password',
              autoFocus: true,
              autoComplete: 'off',
              value: password,
              placeholder: t('lock.placeholder'),
              onChange: (event) => setPassword(event.target.value),
            }),
            h('button', { type: 'submit', className: 'tv-lockButton', disabled: busy || password === '' }, busy ? t('lock.unlocking') : t('lock.submit')),
          ),
        ),
      )
    }

    /** Full-page shell so the vault also works as a `main` panel (hub tab). */
    /** Whether the page shell has learned the lock state yet (per browser session). */
    let vaultSecurityProbed = false

    function TokenPage() {
      useSyncExternalStore(subscribeVaultSecurity, getVaultSecurityRevision)
      const [probed, setProbed] = useState(vaultSecurityProbed)
      useEffect(() => {
        if (probed) return undefined
        let alive = true
        call(LIST_ROUTE)
          .then((payload) => {
            if (!alive) return
            publishVaultSecurity(payload.encrypted === true, payload.locked === true)
            vaultSecurityProbed = true
            setProbed(true)
          })
          .catch(() => {
            // An unreachable Host renders the panel; its own fetch shows the error.
            if (!alive) return
            vaultSecurityProbed = true
            setProbed(true)
          })
        return () => {
          alive = false
        }
      }, [probed])
      if (!probed) {
        // One quiet frame while the lock state is fetched — never the panel
        // itself, so a locked vault cannot flash its contents.
        return h(
          React.Fragment,
          null,
          h(ToastHost),
          h(
            'div',
            { className: 'tv-page' },
            h('style', { key: 'page-style' }, PAGE_STYLE),
            h('div', { className: 'tv-page-inner' }, h('p', { className: 'tv-empty' }, t('lock.checking'))),
          ),
        )
      }
      if (vaultSecurity.encrypted && vaultSecurity.locked) {
        return h(React.Fragment, null, h(ToastHost), h(VaultLockScreen))
      }
      return h(
        React.Fragment,
        null,
        h(ToastHost),
        h(
          'div',
          { className: 'tv-page' },
          h('style', { key: 'page-style' }, PAGE_STYLE),
          h('div', { className: 'tv-page-inner' }, h(TokenSection)),
        ),
      )
    }

    /** Sidebar glyph: a key. */
    function VaultIcon({ size = 18, active = false }) {
      return h(
        'svg',
        {
          width: size,
          height: size,
          viewBox: '0 0 24 24',
          fill: 'none',
          'aria-hidden': true,
          focusable: 'false',
          style: { opacity: active ? 1 : 0.8 },
        },
        h('circle', { cx: 8.4, cy: 12, r: 3.6, stroke: 'currentColor', strokeWidth: 1.7 }),
        h('path', {
          d: 'M12 12h8.2M17.4 12v2.9M20.2 12v2.2',
          stroke: 'currentColor',
          strokeWidth: 1.7,
          strokeLinecap: 'round',
        }),
      )
    }

    return {
      inject: ['slots', 'locale'],
      apply(ctx) {
        client = ctx
        t = ctx.locale.bind(LOCALE_NS)
        ctx.effect(() => ctx.locale.register(LOCALE_NS, DICTIONARIES))
        // Pending confirmations are polled for the whole GUI lifetime (not only
        // while this panel is mounted) so approvals notify the user anywhere:
        // title flash plus the optional sound and desktop notification.
        ctx.effect(() => {
          pollPending()
          const timer = setInterval(pollPending, PENDING_POLL_MS)
          const onVisible = () => {
            if (document.visibilityState === 'visible') pollPending()
          }
          document.addEventListener('visibilitychange', onVisible)
          window.addEventListener('focus', pollPending)
          return () => {
            clearInterval(timer)
            document.removeEventListener('visibilitychange', onVisible)
            window.removeEventListener('focus', pollPending)
          }
        })
        // The panel itself: a hub (or any collector) picks it up from the
        // sidebar list and renders it as its own tab.
        ctx.slots.inject('main', () =>
          ctx.slots.register({ name: 'main', key: PAGE_ID, locale: LOCALE_NS }, TokenPage),
        )
        ctx.slots.inject('sidebar.panellist', () =>
          ctx.slots.register(
            { name: 'sidebar.panellist', id: PAGE_ID, order: 40, locale: LOCALE_NS, label: () => t('nav') },
            VaultIcon,
          ),
        )
      },
    }
  },
})
