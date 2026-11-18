/**
 * Token vault — the Host half.
 *
 * A small local store for Git and other API tokens, plus the one mechanism that
 * lets any Session use a token without the value entering the Session: the
 * `vault_sh` tool runs a command with the stored tokens exported as environment
 * variables. The command text names only the variable (`$GITHUB_TOKEN`), so the
 * value never reaches arguments, the durable session log, a job record, or a
 * receipt.
 *
 * Tool results are additionally scrubbed (`tools/post-execute`): if a command
 * echoes a variable, the value in the output is replaced by {{token:NAME}} —
 * including URL-encoded, base64, base64url, hex and JSON-escaped variants.
 *
 * Placeholders are NOT substituted into tool arguments. That design leaked: the
 * jobs registry stores the dispatched command as a job label, so the substituted
 * value landed in a durable `job/registered` event and came back through job
 * receipts. `tools/pre-execute` refuses placeholder references outright.
 *
 * The value itself is never returned by any route or tool: the panel reads
 * names, notes and value lengths; the agent tools read names and notes. The
 * single exception is the panel's explicit export action, which can require a
 * typed confirmation for plain exports.
 *
 * Storage can stay plaintext (a `0600` JSON document) or be encrypted at rest
 * with a master password (scrypt + AES-256-GCM, one unlock per Host boot).
 *
 * @module @local/token-vault
 */

import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  randomUUID,
  scrypt,
  timingSafeEqual,
} from 'node:crypto'
import { copyFile, mkdir, readFile, rename, stat, unlink, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, isAbsolute, join, sep } from 'node:path'
import { promisify } from 'node:util'

/** Cordis plugin name. */
export const name = 'token-vault'

/** The trust fence, the tool registry, the prompt, the shell, and the jobs registry for `vault_sh` background runs. */
export const inject = ['webServer', 'connection', 'tools', 'systemPrompt', 'shell', 'workingDirectory', 'shellEnv']

/** Accepted token names: a shell-friendly identifier. */
const NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/

/** One `{{token:NAME}}` placeholder occurrence (refused in the tools that execute a string). */
const PLACEHOLDER_PATTERN = /\{\{\s*token\s*:\s*([A-Za-z_][A-Za-z0-9_.-]{0,63})\s*\}\}/g

/** Longest accepted token value. */
const MAX_VALUE_LENGTH = 8192

/** Longest accepted note. */
const MAX_NOTE_LENGTH = 500

/** Longest accepted request-source line (the agent's justification for a save request). */
const MAX_SOURCE_LENGTH = 300

/** Longest accepted check URL. */
const MAX_CHECK_URL_LENGTH = 500

/** Longest accepted check header template. */
const MAX_CHECK_HEADER_LENGTH = 200

/** Request bodies are tiny JSON objects; anything larger is hostile. */
const MAX_BODY_BYTES = 64 * 1024

/** An import carries every token in one body; it gets its own, larger ceiling. */
const MAX_IMPORT_BYTES = 2 * 1024 * 1024

/** Most tokens one import may bring in. */
const MAX_IMPORT_TOKENS = 500

/** Export document discriminator and version. */
const EXPORT_FORMAT = 'token-vault/export'
const EXPORT_VERSION = 1

/** Key-derivation parameters for encrypted material (scrypt, Node builtin). */
const KDF = { name: 'scrypt', N: 16384, r: 8, p: 1, keylen: 32 }

/** Cipher used for encrypted exports and the encrypted vault file. */
const CIPHER = 'aes-256-gcm'

/** Shortest and longest accepted master password. */
const MIN_PASSWORD_LENGTH = 8
const MAX_PASSWORD_LENGTH = 256

/** Values shorter than this are never scrubbed — they are too likely to be ordinary text. */
const MIN_SCRUB_LENGTH = 8

/** Values longer than this skip the hex scrub variant: too costly for too little. */
const MAX_HEX_SCRUB_LENGTH = 512

/** How long a `vault_sh` call waits for the user's approval before giving up. */
const APPROVAL_TIMEOUT_MS = 120_000

/** Shell variable names a token may not take over: exporting one would break
 * the child's PATH lookup or, for BASH_ENV/ENV, let bash source attacker text
 * before the command runs. */
const RESERVED_ENV_NAMES = new Set([
  'PATH', 'HOME', 'PWD', 'SHELL', 'IFS', 'BASH_ENV', 'ENV', 'CDPATH',
  'LD_PRELOAD', 'LD_LIBRARY_PATH', 'NODE_OPTIONS', 'PYTHONPATH', 'PYTHONHOME',
  'TMPDIR', 'USER', 'LOGNAME', 'SHLVL', '_',
])

/** Most confirmations held in memory at once. */
const MAX_PENDING = 100

/** The typed confirmation a plain (unencrypted) export requires. */
const EXPORT_CONFIRMATION = 'EXPORT'

/** The audit log rotates once it reaches this size. */
const AUDIT_MAX_BYTES = 10 * 1024 * 1024

/**
 * Tools that execute a caller-supplied string. Only these refuse a placeholder
 * reference: everywhere else the text is inert (a prompt, a document), and
 * denying it would break documentation and hand-offs between agents.
 */
const PLACEHOLDER_GUARDED = new Set(['bash', 'run_code'])

/** Route paths served to the panel (the browser addresses them document-relative). */
const LIST_PATH = '/token-vault/list'
const SAVE_PATH = '/token-vault/save'
const DELETE_PATH = '/token-vault/delete'
const RENAME_PATH = '/token-vault/rename'
const EXPORT_PATH = '/token-vault/export'
const IMPORT_PATH = '/token-vault/import'
const IMPORT_ENV_PATH = '/token-vault/import-env'
const SETTINGS_PATH = '/token-vault/settings'
const ENCRYPT_PATH = '/token-vault/encrypt'
const DISABLE_ENCRYPTION_PATH = '/token-vault/disable-encryption'
const UNLOCK_PATH = '/token-vault/unlock'
const LOCK_PATH = '/token-vault/lock'
const DELETE_BACKUP_PATH = '/token-vault/delete-backup'
const PENDING_PATH = '/token-vault/pending'
const HISTORY_PATH = '/token-vault/history'
const HISTORY_CLEAR_PATH = '/token-vault/history/clear'
const HISTORY_DELETE_PATH = '/token-vault/history/delete'
const RESOLVE_PATH = '/token-vault/resolve'
const CHECK_PATH = '/token-vault/check'

/** The shell tool: the only way a token reaches a command. */
const SHELL_TOOL_NAME = 'vault_sh'

/** The catalogue tool: names and notes only, plus agent save requests. */
const TOOL_NAME = 'token_vault'

/** The env variable a token's health check uses instead of the real name. */
const CHECK_ENV = 'TV_CHECK'

/** Default check header template when a token does not carry its own. */
const DEFAULT_CHECK_HEADER = `Authorization: Bearer $${CHECK_ENV}`

/**
 * Built-in check endpoints for well-known token names: a name pattern's first
 * match supplies the URL (and optionally a header) when the token has none.
 * Conservative by design — only unambiguous providers.
 */
const DEFAULT_CHECKS = [
  { pattern: /GITHUB/i, url: 'https://api.github.com/user', header: DEFAULT_CHECK_HEADER },
  { pattern: /GITLAB/i, url: 'https://gitlab.com/api/v4/user', header: DEFAULT_CHECK_HEADER },
  { pattern: /(HUGGINGFACE|HF)_TOKEN/i, url: 'https://huggingface.co/api/whoami-v2', header: DEFAULT_CHECK_HEADER },
  { pattern: /SLACK_TOKEN/i, url: 'https://slack.com/api/auth.test', header: DEFAULT_CHECK_HEADER },
  { pattern: /CLOUDFLARE/i, url: 'https://api.cloudflare.com/client/v4/user/tokens/verify', header: `Authorization: Bearer $${CHECK_ENV}` },
]

/** The default check for one token name, or undefined. */
function defaultCheck(tokenName) {
  return DEFAULT_CHECKS.find((entry) => entry.pattern.test(tokenName))
}

/**
 * The vault file this profile uses unless the row's `config.file` overrides it.
 *
 * One file per user, under `$DSH_HOME`: the point of the vault is that every
 * Session (and every profile of this user) can resolve the same token, so the
 * store is deliberately not profile-scoped.
 */
function defaultFile() {
  const home = process.env.DSH_HOME
  const directory = typeof home === 'string' && home !== '' ? home : join(homedir(), '.dsh')
  return join(directory, 'token-vault.json')
}

/** The audit log path unless `config.auditFile` overrides it. */
function defaultAuditFile() {
  const home = process.env.DSH_HOME
  const directory = typeof home === 'string' && home !== '' ? home : join(homedir(), '.dsh')
  return join(directory, 'token-vault-audit.jsonl')
}

/** The persisted approval history unless `config.approvalsFile` overrides it. */
function defaultApprovalsFile() {
  const home = process.env.DSH_HOME
  const directory = typeof home === 'string' && home !== '' ? home : join(homedir(), '.dsh')
  return join(directory, 'token-vault-approvals.json')
}

/** The session projection cache the GUI's session list reads from. */
function defaultProjCacheDir() {
  const home = process.env.DSH_HOME
  const directory = typeof home === 'string' && home !== '' ? home : join(homedir(), '.dsh')
  return join(directory, 'storages', 'session_projcache', 'sessions')
}

/** A rejection carrying the reason the panel shows verbatim. */
class VaultError extends Error {
  /**
   * @param message - user-facing reason.
   */
  constructor(message) {
    super(message)
    this.name = 'VaultError'
  }
}

/** Whether one date-like string parses into a real instant. */
function isInstant(value) {
  return typeof value === 'string' && value !== '' && !Number.isNaN(new Date(value).getTime())
}

/** The value-free projection every caller may see. */
function publicEntry(entry) {
  const out = {
    name: entry.name,
    note: entry.note,
    length: entry.value.length,
    createdAt: entry.createdAt,
    updatedAt: entry.updatedAt,
    enabled: entry.enabled !== false,
  }
  if (entry.expiresAt !== undefined) out.expiresAt = entry.expiresAt
  if (entry.checkUrl !== undefined) out.checkUrl = entry.checkUrl
  if (entry.checkHeader !== undefined) out.checkHeader = entry.checkHeader
  if (entry.lastUsedAt !== undefined) out.lastUsedAt = entry.lastUsedAt
  if (entry.lastUsedBy !== undefined) out.lastUsedBy = entry.lastUsedBy
  return out
}

/** Validate one optional expiry instant; `undefined` and `null` clear it. */
function normalizeExpiresAt(raw) {
  if (raw === undefined || raw === null || raw === '') return undefined
  if (!isInstant(raw)) throw new VaultError('有效期必须是合法日期')
  return new Date(raw).toISOString()
}

/** Validate one optional check URL; `undefined`, `null` and `''` clear it. */
function normalizeCheckUrl(raw) {
  if (raw === undefined || raw === null || raw === '') return undefined
  if (typeof raw !== 'string' || raw.length > MAX_CHECK_URL_LENGTH || !/^https?:\/\/\S+$/i.test(raw) || /["'`\\$]/.test(raw)) {
    throw new VaultError('检查 URL 必须是 http(s) 地址，且不能包含引号、反斜杠或 shell 变量')
  }
  return raw
}

/** Validate one optional check header template; it must carry the check env variable. */
function normalizeCheckHeader(raw) {
  if (raw === undefined || raw === null || raw === '') return undefined
  if (typeof raw !== 'string' || raw.length > MAX_CHECK_HEADER_LENGTH) {
    throw new VaultError(`检查请求头最多 ${MAX_CHECK_HEADER_LENGTH} 个字符`)
  }
  if (!/^[\x20-\x7E]+$/.test(raw) || /["'`\\]/.test(raw)) {
    throw new VaultError('检查请求头只能是可打印 ASCII，不能含引号、反斜杠或反引号')
  }
  if (/\$(?!TV_CHECK\b)/.test(raw)) {
    throw new VaultError(`检查请求头只能使用 $${CHECK_ENV} 这个变量`)
  }
  if (!raw.includes(`$${CHECK_ENV}`)) {
    throw new VaultError(`检查请求头必须引用 $${CHECK_ENV}，这样才能注入令牌值`)
  }
  return raw
}

/**
 * Validate one load-time check field; anything that does not pass the same
 * rules as the save routes is dropped instead of rejecting the whole entry.
 * This is the load-time fence against a hand-edited or imported vault file
 * smuggling shell text into the health-check command.
 *
 * @param normalize - the save-route validator.
 * @param raw - the field value read from disk.
 * @returns the value when valid, otherwise undefined.
 */
function tryCheckField(normalize, raw) {
  try {
    return normalize(raw)
  } catch {
    return undefined
  }
}

/** Normalize one stored record, refusing anything that is not a usable token. */
function normalizeEntry(name, raw, now) {
  const value = typeof raw?.value === 'string' ? raw.value : ''
  return {
    name,
    value,
    note: typeof raw?.note === 'string' ? raw.note : '',
    enabled: raw?.enabled === false ? false : true,
    expiresAt: isInstant(raw?.expiresAt) ? new Date(raw.expiresAt).toISOString() : undefined,
    checkUrl: tryCheckField(normalizeCheckUrl, raw?.checkUrl),
    checkHeader: tryCheckField(normalizeCheckHeader, raw?.checkHeader),
    lastUsedAt: isInstant(raw?.lastUsedAt) ? raw.lastUsedAt : undefined,
    lastUsedBy: typeof raw?.lastUsedBy === 'string' && raw.lastUsedBy !== '' ? raw.lastUsedBy : undefined,
    createdAt: typeof raw?.createdAt === 'string' ? raw.createdAt : now,
    updatedAt: typeof raw?.updatedAt === 'string' ? raw.updatedAt : now,
  }
}

/** Default settings for a fresh or legacy vault. */
function defaultSettings() {
  return { requireApproval: false, audit: true, approvalUI: 'session' }
}

/** Sanitize settings read from a document. */
function normalizeSettings(raw) {
  const base = defaultSettings()
  if (raw !== null && typeof raw === 'object') {
    if (typeof raw.requireApproval === 'boolean') base.requireApproval = raw.requireApproval
    if (typeof raw.audit === 'boolean') base.audit = raw.audit
    if (raw.approvalUI === 'session' || raw.approvalUI === 'panel') base.approvalUI = raw.approvalUI
  }
  return base
}

/** A shuffled base64 string is not enough for a key; refuse unusable derivation material. */
function decodeBase64(value, expectedLength) {
  if (typeof value !== 'string' || value === '') return undefined
  const bytes = Buffer.from(value, 'base64')
  return expectedLength === undefined || bytes.length === expectedLength ? bytes : undefined
}

const scryptAsync = promisify(scrypt)

/**
 * Derive the 256-bit master key from a password and the stored salt.
 *
 * @param password - user-chosen password.
 * @param salt - 16-byte salt.
 * @returns the derived key.
 */
async function deriveKey(password, salt) {
  return scryptAsync(password, salt, KDF.keylen, { N: KDF.N, r: KDF.r, p: KDF.p })
}

/**
 * Encrypt one document with a key: AES-256-GCM authenticates the ciphertext,
 * so a wrong password or a truncated file fails closed instead of yielding
 * garbage.
 *
 * @param plaintext - the document bytes.
 * @param key - the derived key.
 * @param iv - 12-byte IV.
 * @returns cipher fields for the envelope.
 */
function encryptWithKey(plaintext, key, iv) {
  const cipher = createCipheriv(CIPHER, key, iv)
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
  return { ciphertext, tag: cipher.getAuthTag() }
}

/**
 * Decrypt one AES-256-GCM envelope with a key.
 *
 * @param ciphertext - encrypted bytes.
 * @param key - the derived key.
 * @param iv - 12-byte IV.
 * @param tag - 16-byte auth tag.
 * @returns the plaintext bytes.
 * @throws {VaultError} when the envelope does not authenticate.
 */
function decryptWithKey(ciphertext, key, iv, tag) {
  try {
    const decipher = createDecipheriv(CIPHER, key, iv)
    decipher.setAuthTag(tag)
    return Buffer.concat([decipher.update(ciphertext), decipher.final()])
  } catch {
    throw new VaultError('无法解密：密码不对，或者文件已损坏')
  }
}

/**
 * Encrypt one export document with a password.
 *
 * @param document - the plaintext export document.
 * @param password - user-chosen password.
 * @returns the encrypted envelope the panel downloads.
 */
async function encryptExport(document, password) {
  const salt = randomBytes(16)
  const iv = randomBytes(12)
  const key = await deriveKey(password, salt)
  const { ciphertext, tag } = encryptWithKey(Buffer.from(JSON.stringify(document), 'utf8'), key, iv)
  return {
    format: EXPORT_FORMAT,
    version: EXPORT_VERSION,
    encrypted: true,
    exportedAt: new Date().toISOString(),
    kdf: { ...KDF, salt: salt.toString('base64') },
    cipher: { name: CIPHER, iv: iv.toString('base64'), tag: tag.toString('base64') },
    ciphertext: ciphertext.toString('base64'),
  }
}

/**
 * Decrypt one encrypted export envelope with a password.
 *
 * @param envelope - the parsed file content.
 * @param password - user-supplied password.
 * @returns the plaintext export document.
 * @throws {VaultError} when the envelope is malformed or the password is wrong.
 */
async function decryptExport(envelope, password) {
  const kdf = envelope.kdf ?? {}
  const cipher = envelope.cipher ?? {}
  if (kdf.name !== KDF.name || Number(kdf.N) !== KDF.N || Number(kdf.r) !== KDF.r || Number(kdf.p) !== KDF.p) {
    throw new VaultError('不支持的加密导出文件：未知的密钥派生参数')
  }
  const keylen = Number(kdf.keylen)
  if (!Number.isInteger(keylen) || keylen < 16 || keylen > 64) throw new VaultError('不支持的加密导出文件：未知的密钥长度')
  const salt = decodeBase64(kdf.salt, 16)
  const iv = decodeBase64(cipher.iv, 12)
  const tag = decodeBase64(cipher.tag, 16)
  const ciphertext = decodeBase64(envelope.ciphertext)
  if (salt === undefined || iv === undefined || tag === undefined || ciphertext === undefined) {
    throw new VaultError('导出文件已损坏：缺少 Base64 字段或无法读取')
  }
  const key = await scryptAsync(password, salt, keylen, { N: KDF.N, r: KDF.r, p: KDF.p })
  return JSON.parse(decryptWithKey(ciphertext, key, iv, tag).toString('utf8'))
}

/**
 * Validate one decoded export document into importable entries.
 *
 * Fails closed: one bad entry rejects the whole import, so a partially imported
 * vault never replaces a good one.
 *
 * @param document - the plaintext export document.
 * @returns the accepted entries.
 * @throws {VaultError} when the document is not a token-vault export or holds an invalid entry.
 */
function parseImportDocument(document) {
  if (document === null || typeof document !== 'object') throw new VaultError('这个文件不是令牌库导出的文件')
  if (document.format !== undefined && document.format !== EXPORT_FORMAT) {
    throw new VaultError('这个文件不是令牌库导出的文件')
  }
  const list = Array.isArray(document.tokens) ? document.tokens : []
  if (list.length === 0) throw new VaultError('导出文件里没有令牌')
  if (list.length > MAX_IMPORT_TOKENS) throw new VaultError(`导出文件里的令牌超过 ${MAX_IMPORT_TOKENS} 个`)
  const invalid = []
  const entries = []
  for (const raw of list) {
    const entry = coerceEntry(raw)
    if (entry === undefined) {
      invalid.push(typeof raw?.name === 'string' && raw.name !== '' ? raw.name : '(unnamed)')
      continue
    }
    entries.push(entry)
  }
  if (invalid.length > 0) throw new VaultError(`导出文件里有不合法的条目：${invalid.join('、')}`)
  return entries
}

/**
 * Coerce one loose record into an importable entry, or undefined when invalid.
 *
 * @param raw - candidate record.
 * @returns the entry, or undefined when the record is not usable.
 */
function coerceEntry(raw) {
  const tokenName = typeof raw?.name === 'string' ? raw.name : ''
  const value = typeof raw?.value === 'string' ? raw.value : ''
  const note = typeof raw?.note === 'string' ? raw.note : ''
  if (!NAME_PATTERN.test(tokenName) || RESERVED_ENV_NAMES.has(tokenName) || value === '' || value.length > MAX_VALUE_LENGTH || note.length > MAX_NOTE_LENGTH) return undefined
  const entry = { name: tokenName, value, note }
  if (raw.enabled === false) entry.enabled = false
  const expiresAt = normalizeExpiresAt(raw.expiresAt)
  if (expiresAt !== undefined) entry.expiresAt = expiresAt
  const checkUrl = normalizeCheckUrl(raw.checkUrl)
  if (checkUrl !== undefined) entry.checkUrl = checkUrl
  const checkHeader = normalizeCheckHeader(raw.checkHeader)
  if (checkHeader !== undefined) entry.checkHeader = checkHeader
  return entry
}

/** Resolve a relative per-call workdir against the Session's current directory. */
function resolveWorkdir(modelWorkdir, sessionCwd) {
  if (modelWorkdir === undefined) return sessionCwd
  if (sessionCwd !== undefined && !isAbsolute(modelWorkdir)) return `${sessionCwd}${sep}${modelWorkdir}`
  return modelWorkdir
}

/** Friendly display name of one token (the raw name stays available in the panel). */
function tokenLabel(tokenName) {
  const known = {
    GITHUB_TOKEN: 'GitHub 令牌',
    GITLAB_TOKEN: 'GitLab 令牌',
    NPM_TOKEN: 'npm 令牌',
    SLACK_TOKEN: 'Slack 令牌',
    HUGGINGFACE_TOKEN: 'Hugging Face 令牌',
  }
  return known[tokenName] ?? tokenName
}

/**
 * A plain-language brief of one pending vault_sh approval. Deliberately short —
 * no command text; the full command lives in the panel's expandable detail and
 * the audit log, and values never appear anywhere.
 *
 * The session card omits the "which session" line (the card is already in that
 * session); the panel queue keeps it because requests from every session land
 * in one list there.
 *
 * @param payload - description, command, token names, session info.
 * @param options - `withSession`: mention the requesting session (panel mode).
 * @returns the human-readable summary text.
 */
function approvalBrief(payload) {
  const parts = ['当前轮次调用需要使用下你的令牌。']
  const tokens = payload.tokens ?? []
  if (tokens.length > 0) {
    const names = tokens.map(tokenLabel)
    parts.push(`会用到：${names.length > 3 ? `${names.slice(0, 3).join('、')} 等 ${names.length} 个` : names.join('、')}。`)
  }
  // Only show the agent's own description when it is in the user's language:
  // an English-only line (the tool's default habit before 1.6.1) is noise on a
  // Chinese card, so it is omitted rather than pasted. The exact purpose stays
  // visible in the panel and the audit log.
  const description = (payload.description ?? '').trim()
  if (description !== '' && /[\u4e00-\u9fff]/.test(description)) parts.push(`要做什么：${description}`)
  parts.push('批准后这条命令才会执行。令牌只临时给它用，聊天记录里看不到。')
  return parts.join('\n')
}

/**
 * The vault: one JSON document, read once, written atomically with owner-only
 * permissions, and mirrored in memory for the placeholder and scrub paths.
 *
 * The document is plaintext (`{version:1, settings, tokens}`) until encryption
 * is enabled; then it becomes an envelope (`{version:2, encrypted:true, …}`)
 * whose payload only exists in memory between an unlock and the next lock.
 */
class TokenVault {
  tokens = new Map()

  /** Scrub variants per secret, longest value first so a prefix never wins over its superstring. */
  secrets = []

  /** Whether the document on disk is (or will be) encrypted. */
  encrypted = false

  /** Key-derivation block of the current envelope (undefined in plaintext mode). */
  kdf

  /** The unlocked master key (undefined while locked or in plaintext mode). */
  key

  /** Whether an encrypted document is waiting for its master password. */
  locked = false

  settings = defaultSettings()

  loading

  writing = Promise.resolve()

  /**
   * @param file - absolute path of the JSON document.
   * @param auditFile - absolute path of the JSONL audit log.
   * @param logger - the plugin's logger.
   */
  constructor(file, auditFile, logger) {
    this.file = file
    this.auditFile = auditFile
    this.logger = logger
  }

  /** Load once; every later caller reuses the same promise. */
  ready() {
    this.loading ??= this.read()
    return this.loading
  }

  async read() {
    let text
    try {
      text = await readFile(this.file, 'utf8')
    } catch (error) {
      if (error?.code === 'ENOENT') return
      throw error
    }
    let parsed
    try {
      parsed = JSON.parse(text)
    } catch (error) {
      this.logger?.warn?.(`token-vault: ${this.file} is not valid JSON; starting with an empty vault (${String(error)})`)
      this.reindex()
      return
    }
    if (parsed !== null && typeof parsed === 'object' && parsed.encrypted === true) {
      // An encrypted document: stay locked until the master password arrives.
      this.encrypted = true
      this.locked = true
      this.kdf = parsed.kdf
      this.envelope = parsed
      this.reindex()
      return
    }
    this.encrypted = false
    this.locked = false
    this.settings = normalizeSettings(parsed?.settings)
    const records = parsed?.tokens
    if (records !== null && typeof records === 'object') {
      const now = new Date().toISOString()
      for (const [key, raw] of Object.entries(records)) {
        if (!NAME_PATTERN.test(key)) continue
        const entry = normalizeEntry(key, raw, now)
        if (entry.value === '') continue
        this.tokens.set(key, entry)
      }
    }
    this.reindex()
  }

  /** Rebuild the scrub index from the current records. */
  reindex() {
    this.secrets = [...this.tokens.values()]
      .filter((entry) => entry.enabled !== false && entry.value.length >= MIN_SCRUB_LENGTH)
      .map((entry) => ({ name: entry.name, variants: scrubVariants(entry.value) }))
      .sort((left, right) => right.variants[0].length - left.variants[0].length)
  }

  /** Whether calls that need values may run right now. */
  unlockedOrPlain() {
    return !this.encrypted || !this.locked
  }

  /** Guard for every operation that reads or writes values. */
  requireUnlocked() {
    if (!this.unlockedOrPlain()) {
      throw new VaultError('令牌库已上锁 —— 请先在令牌库面板输入主密码解锁')
    }
  }

  /**
   * Open an encrypted vault with its master password.
   *
   * @param password - the master password chosen when encryption was enabled.
   */
  async unlock(password) {
    await this.ready()
    if (!this.encrypted) throw new VaultError('令牌库没有加密，不需要解锁')
    if (!this.locked) throw new VaultError('令牌库已经是解锁状态')
    if (typeof password !== 'string' || password.length === 0) throw new VaultError('请填写主密码')
    const envelope = this.envelope
    const salt = decodeBase64(envelope?.kdf?.salt, 16)
    const iv = decodeBase64(envelope?.cipher?.iv, 12)
    const tag = decodeBase64(envelope?.cipher?.tag, 16)
    const ciphertext = decodeBase64(envelope?.ciphertext)
    if (salt === undefined || iv === undefined || tag === undefined || ciphertext === undefined) {
      throw new VaultError('库文件已损坏：缺少 Base64 字段或无法读取')
    }
    const key = await deriveKey(password, salt)
    const payload = JSON.parse(decryptWithKey(ciphertext, key, iv, tag).toString('utf8'))
    this.settings = normalizeSettings(payload?.settings)
    const records = payload?.tokens
    if (records !== null && typeof records === 'object') {
      const now = new Date().toISOString()
      for (const [name, raw] of Object.entries(records)) {
        if (!NAME_PATTERN.test(name)) continue
        const entry = normalizeEntry(name, raw, now)
        if (entry.value === '') continue
        this.tokens.set(name, entry)
      }
    }
    this.key = key
    this.locked = false
    this.reindex()
  }

  /** Forget every value and the master key; the document stays on disk encrypted. */
  lock() {
    if (!this.encrypted) throw new VaultError('令牌库没有加密，不需要上锁')
    this.tokens.clear()
    this.secrets = []
    this.key = undefined
    this.settings = defaultSettings()
    this.locked = true
  }

  /**
   * Turn on at-rest encryption (or change the master password of an already
   * encrypted, unlocked vault). Converting a plaintext vault first copies it to
   * a `0600` backup next to the file; the caller deletes the backup once the
   * user confirms everything is fine.
   *
   * @param password - the new master password.
   * @returns whether a plaintext backup was left behind.
   */
  async enableEncryption(password) {
    await this.ready()
    this.requireUnlocked()
    if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH) {
      throw new VaultError(`主密码至少 ${MIN_PASSWORD_LENGTH} 个字符`)
    }
    if (password.length > MAX_PASSWORD_LENGTH) {
      throw new VaultError(`主密码最多 ${MAX_PASSWORD_LENGTH} 个字符`)
    }
    const wasEncrypted = this.encrypted
    // Snapshot the live key material so a failed conversion/changing restores
    // both memory and disk instead of leaving a half-switched vault behind.
    const previous = { encrypted: this.encrypted, key: this.key, kdf: this.kdf, envelope: this.envelope }
    const backupPath = `${this.file}.pre-encryption.bak`
    let backup = false
    if (!wasEncrypted) {
      // Best-effort probe: only keep a backup when a plaintext file exists.
      let plaintextExists = false
      try {
        await stat(this.file)
        plaintextExists = true
      } catch {
        plaintextExists = false
      }
      if (plaintextExists) {
        await copyFile(this.file, backupPath)
        backup = true
      }
    }
    const salt = randomBytes(16)
    this.kdf = { ...KDF, salt: salt.toString('base64') }
    this.key = await deriveKey(password, salt)
    this.encrypted = true
    let wroteNewFile = false
    try {
      await this.flush()
      wroteNewFile = true
      // Verify the round trip before trusting the encrypted file.
      const text = await readFile(this.file, 'utf8')
      const envelope = JSON.parse(text)
      const saltBytes = decodeBase64(envelope.kdf?.salt, 16)
      const iv = decodeBase64(envelope.cipher?.iv, 12)
      const tag = decodeBase64(envelope.cipher?.tag, 16)
      const ciphertext = decodeBase64(envelope.ciphertext)
      if (saltBytes === undefined || iv === undefined || tag === undefined || ciphertext === undefined) {
        throw new VaultError('加密的库文件已损坏：缺少 Base64 字段或无法读取')
      }
      const payload = JSON.parse(decryptWithKey(ciphertext, this.key, iv, tag).toString('utf8'))
      const count = payload?.tokens !== null && typeof payload?.tokens === 'object' ? Object.keys(payload.tokens).length : -1
      if (count !== this.tokens.size) throw new VaultError('加密后的库文件无法正确还原')
    } catch (error) {
      // Restore the pre-attempt state: memory first, then disk. The envelope
      // matters too — a later lock/unlock decrypts with in-memory key material,
      // so a stale new-ciphertext envelope would fail the old password.
      this.encrypted = previous.encrypted
      this.key = previous.key
      this.kdf = previous.kdf
      this.envelope = previous.envelope
      if (!wasEncrypted) {
        // Converting a plaintext vault failed: put the plaintext file back.
        if (backup) await copyFile(backupPath, this.file)
      } else if (wroteNewFile) {
        // Changing the password failed after the new envelope hit the disk:
        // rewrite the previous envelope with the previous key.
        try {
          await this.flush()
        } catch (restoreError) {
          this.logger?.warn?.(`token-vault: cannot restore the previous envelope after a failed password change: ${String(restoreError)}`)
        }
      }
      const failedAction = wasEncrypted ? '更换主密码' : '加密'
      if (error instanceof VaultError) {
        throw new VaultError(`${failedAction}失败，令牌库已恢复原样（${error.message}）`)
      }
      throw new VaultError(`${failedAction}失败，令牌库已恢复原样`)
    }
    return { backup, backupPath: backup ? backupPath : undefined }
  }

  /**
   * Turn off at-rest encryption after verifying the master password.
   *
   * @param password - the current master password.
   */
  async disableEncryption(password) {
    await this.ready()
    if (!this.encrypted) throw new VaultError('当前没有开启加密')
    this.requireUnlocked()
    if (typeof password !== 'string' || password.length === 0) throw new VaultError('关闭加密需要填写主密码')
    const salt = decodeBase64(this.kdf?.salt, 16)
    if (salt === undefined) throw new VaultError('库文件已损坏：缺少 Base64 字段或无法读取')
    const candidate = await deriveKey(password, salt)
    const matches = this.key !== undefined && candidate.length === this.key.length && timingSafeEqual(candidate, this.key)
    if (!matches) throw new VaultError('主密码不对')
    this.encrypted = false
    this.key = undefined
    this.kdf = undefined
    await this.flush()
  }

  /** Every stored token, value-free, ordered by name. */
  list() {
    return [...this.tokens.values()].map(publicEntry).sort((left, right) => left.name.localeCompare(right.name, 'en'))
  }

  /** The stored value, or undefined. Host-side callers only — never a route or tool result. */
  resolve(tokenName) {
    return this.tokens.get(tokenName)?.value
  }

  /**
   * Create or update one record. An omitted `value` keeps the current one;
   * omitted fields keep their current values; a new token needs a value.
   *
   * @param input - validated name and optional fields.
   * @returns the value-free projection plus any duplicate-value warning.
   */
  async save(input) {
    await this.ready()
    this.requireUnlocked()
    if (RESERVED_ENV_NAMES.has(input.name)) {
      throw new VaultError(`「${input.name}」是系统保留的变量名，不能作为令牌名`)
    }
    const existing = this.tokens.get(input.name)
    const value = input.value === undefined ? existing?.value : input.value
    if (value === undefined || value === '') {
      throw new VaultError(`「${input.name}」还不存在 —— 需要填写令牌值`)
    }
    if (value.length > MAX_VALUE_LENGTH) throw new VaultError(`令牌值最多 ${MAX_VALUE_LENGTH} 个字符`)
    const note = input.note === undefined ? existing?.note ?? '' : input.note
    if (note.length > MAX_NOTE_LENGTH) throw new VaultError(`备注最多 ${MAX_NOTE_LENGTH} 个字符`)
    const enabled = input.enabled === undefined ? existing?.enabled ?? true : input.enabled === true
    const expiresAt = input.expiresAt === undefined
      ? existing?.expiresAt
      : normalizeExpiresAt(input.expiresAt)
    const checkUrl = input.checkUrl === undefined ? existing?.checkUrl : normalizeCheckUrl(input.checkUrl)
    const checkHeader = input.checkHeader === undefined ? existing?.checkHeader : normalizeCheckHeader(input.checkHeader)
    const now = new Date().toISOString()
    const entry = {
      name: input.name,
      value,
      note,
      enabled,
      ...(expiresAt === undefined ? {} : { expiresAt }),
      ...(checkUrl === undefined ? {} : { checkUrl }),
      ...(checkHeader === undefined ? {} : { checkHeader }),
      ...(existing?.lastUsedAt === undefined ? {} : { lastUsedAt: existing.lastUsedAt }),
      ...(existing?.lastUsedBy === undefined ? {} : { lastUsedBy: existing.lastUsedBy }),
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    }
    this.tokens.set(entry.name, entry)
    await this.flush()
    this.reindex()
    const duplicateOf = [...this.tokens.values()]
      .filter((other) => other.name !== entry.name && other.value === value)
      .map((other) => other.name)
    return { token: publicEntry(entry), duplicateOf }
  }

  /**
   * Rename one record, keeping its value, note and history.
   *
   * @param from - current name.
   * @param to - new name.
   * @returns the value-free projection of the renamed record.
   */
  async rename(from, to) {
    await this.ready()
    this.requireUnlocked()
    if (!NAME_PATTERN.test(to)) {
      throw new VaultError('新名称要以字母或下划线开头，只能包含字母、数字、点、横线或下划线')
    }
    if (RESERVED_ENV_NAMES.has(to)) {
      throw new VaultError(`「${to}」是系统保留的变量名，不能作为令牌名`)
    }
    const existing = this.tokens.get(from)
    if (existing === undefined) throw new VaultError(`没有叫「${from}」的令牌`)
    if (this.tokens.has(to)) throw new VaultError(`已经有一个叫「${to}」的令牌了`)
    this.tokens.delete(from)
    const entry = { ...existing, name: to, updatedAt: new Date().toISOString() }
    this.tokens.set(to, entry)
    await this.flush()
    this.reindex()
    return publicEntry(entry)
  }

  /**
   * Delete one record.
   *
   * @param tokenName - record name.
   * @returns whether a record was removed.
   */
  async remove(tokenName) {
    await this.ready()
    this.requireUnlocked()
    const removed = this.tokens.delete(tokenName)
    if (!removed) throw new VaultError(`没有叫「${tokenName}」的令牌`)
    await this.flush()
    this.reindex()
    return true
  }

  /**
   * Every token WITH its value, for the export route only.
   *
   * This is the single place the plugin hands values back out: the panel's
   * explicit export action. No tool, and no other route, can reach it.
   *
   * @returns plain records ordered by name.
   */
  exportAll() {
    this.requireUnlocked()
    return [...this.tokens.values()]
      .sort((left, right) => left.name.localeCompare(right.name, 'en'))
      .map((entry) => ({
        name: entry.name,
        value: entry.value,
        note: entry.note,
        ...(entry.enabled === false ? { enabled: false } : {}),
        ...(entry.expiresAt === undefined ? {} : { expiresAt: entry.expiresAt }),
        ...(entry.checkUrl === undefined ? {} : { checkUrl: entry.checkUrl }),
        ...(entry.checkHeader === undefined ? {} : { checkHeader: entry.checkHeader }),
        createdAt: entry.createdAt,
        updatedAt: entry.updatedAt,
      }))
  }

  /**
   * Merge validated entries from one import.
   *
   * `merge` keeps an existing token untouched; `overwrite` replaces its value
   * and fields but keeps its original creation time. Both add unknown names.
   *
   * @param entries - validated records.
   * @param mode - `merge` or `overwrite`.
   * @returns counts plus the affected names.
   */
  async importEntries(entries, mode) {
    await this.ready()
    this.requireUnlocked()
    const added = []
    const updated = []
    const skipped = []
    const now = new Date().toISOString()
    for (const entry of entries) {
      const existing = this.tokens.get(entry.name)
      if (existing === undefined) {
        this.tokens.set(entry.name, {
          ...entry,
          createdAt: now,
          updatedAt: now,
        })
        added.push(entry.name)
        continue
      }
      if (mode !== 'overwrite') {
        skipped.push(entry.name)
        continue
      }
      this.tokens.set(entry.name, {
        ...entry,
        createdAt: existing.createdAt,
        updatedAt: now,
      })
      updated.push(entry.name)
    }
    if (added.length > 0 || updated.length > 0) {
      await this.flush()
      this.reindex()
    }
    return { added, updated, skipped }
  }

  /** Write the document atomically: a private temp file in the same directory, then rename. */
  flush() {
    let payload
    if (this.encrypted) {
      const envelope = this.envelopeFor()
      // Keep the in-memory envelope current so the next unlock can decrypt
      // without re-reading the file.
      this.envelope = envelope
      payload = `${JSON.stringify(envelope, null, 2)}\n`
    } else {
      payload = `${JSON.stringify({ version: 1, settings: this.settings, tokens: Object.fromEntries(this.tokens) }, null, 2)}\n`
    }
    const file = this.file
    const write = this.writing.then(async () => {
      await mkdir(dirname(file), { recursive: true })
      const temporary = `${file}.${process.pid}.tmp`
      await writeFile(temporary, payload, { encoding: 'utf8', mode: 0o600 })
      await rename(temporary, file)
    })
    // Keep the queue usable after a failed write: the caller still sees the rejection.
    this.writing = write.catch(() => {})
    return write
  }

  /** The encrypted document to write: fresh IV per flush, same derived key. */
  envelopeFor() {
    if (this.key === undefined) throw new VaultError('令牌库已上锁，解锁后才能写入')
    const iv = randomBytes(12)
    const document = { version: 1, settings: this.settings, tokens: Object.fromEntries(this.tokens) }
    const { ciphertext, tag } = encryptWithKey(Buffer.from(JSON.stringify(document), 'utf8'), this.key, iv)
    return {
      version: 2,
      encrypted: true,
      savedAt: new Date().toISOString(),
      kdf: this.kdf,
      cipher: { name: CIPHER, iv: iv.toString('base64'), tag: tag.toString('base64') },
      ciphertext: ciphertext.toString('base64'),
    }
  }

  /** The latest encrypted document read from disk (kept for the unlock route). */
  envelope

  /**
   * Append one audit event to the JSONL log (best-effort, never throws).
   *
   * @param event - the fields to record; values are forbidden by convention.
   */
  async audit(event) {
    if (this.settings.audit !== true) return
    try {
      const line = `${JSON.stringify({ at: new Date().toISOString(), ...event })}\n`
      try {
        const info = await stat(this.auditFile)
        if (info.size > AUDIT_MAX_BYTES) await rename(this.auditFile, `${this.auditFile}.1`)
      } catch {
        // No log yet, or unreadable — appending still works.
      }
      await mkdir(dirname(this.auditFile), { recursive: true })
      await writeFile(this.auditFile, line, { encoding: 'utf8', flag: 'a', mode: 0o600 })
    } catch (error) {
      this.logger?.warn?.(`token-vault: cannot write the audit log: ${String(error)}`)
    }
  }

  /** Record a token's last use (fire-and-forget; a failure must not fail the call). */
  async touch(names, sessionId) {
    if (names.length === 0) return
    const now = new Date().toISOString()
    for (const name of names) {
      const entry = this.tokens.get(name)
      if (entry === undefined) continue
      entry.lastUsedAt = now
      entry.lastUsedBy = sessionId
    }
    try {
      await this.flush()
    } catch (error) {
      this.logger?.warn?.(`token-vault: cannot record last-used stamps: ${String(error)}`)
    }
  }

  /**
   * Collect every placeholder name one argument tree mentions, known or not.
   *
   * @param value - candidate tool arguments.
   * @returns names in first-seen order.
   */
  references(value) {
    const names = new Set()
    const visit = (node) => {
      if (typeof node === 'string') {
        if (!node.includes('{{')) return
        for (const match of node.matchAll(PLACEHOLDER_PATTERN)) names.add(match[1])
        return
      }
      if (Array.isArray(node)) {
        for (const item of node) visit(item)
        return
      }
      if (node !== null && typeof node === 'object') {
        for (const item of Object.values(node)) visit(item)
      }
    }
    visit(value)
    return [...names]
  }

  /**
   * Export tokens into a child environment.
   *
   * Token names allow `.` and `-`, which are not valid in a shell variable, so
   * each name is mapped to a shell-safe one (`.`/`-` become `_`, a leading digit
   * gains a `T_` prefix) and collisions get a numeric suffix. Disabled tokens
   * are skipped unless they are explicitly requested (and enabled).
   *
   * @param onlyNames - export just these validated names; undefined means every enabled token.
   * @returns the environment entries and the name mapping the caller reports.
   */
  environment(onlyNames) {
    const entries = [...this.tokens.values()]
      .filter((entry) => entry.enabled !== false)
      .sort((left, right) => left.name.localeCompare(right.name, 'en'))
    // Assign every enabled token its shell name first, then filter: a subset
    // export must expose the same variable name a full export would, or a
    // caller that reads `$NAME` from the panel would hit a different token
    // whenever the subset changes the collision order.
    const taken = new Set()
    const nameToEnv = new Map()
    for (const entry of entries) {
      let base = entry.name.replace(/[^A-Za-z0-9_]/g, '_')
      if (!/^[A-Za-z_]/.test(base)) base = `T_${base}`
      // A file written by an older version (or hand-edited) may still carry a
      // reserved name; never export it over the shell's own variables.
      if (RESERVED_ENV_NAMES.has(base)) base = `T_${base}`
      let candidate = base
      let suffix = 2
      while (taken.has(candidate)) candidate = `${base}_${suffix++}`
      taken.add(candidate)
      nameToEnv.set(entry.name, candidate)
    }
    const env = {}
    const exports = []
    for (const entry of entries) {
      if (onlyNames !== undefined && !onlyNames.includes(entry.name)) continue
      const variable = nameToEnv.get(entry.name)
      env[variable] = entry.value
      exports.push({ name: entry.name, env: variable, length: entry.value.length })
    }
    return { env, exports }
  }

  /**
   * Scrub stored values out of one string, replacing them with their placeholder.
   *
   * @param text - candidate text.
   * @returns the scrubbed text (the same string when nothing matched).
   */
  scrub(text) {
    if (this.secrets.length === 0 || typeof text !== 'string' || text === '') return text
    let out = text
    for (const secret of this.secrets) {
      for (const variant of secret.variants) {
        if (out.includes(variant)) out = out.split(variant).join(`{{token:${secret.name}}}`)
      }
    }
    return out
  }

  /**
   * Scrub every text block of a content list.
   *
   * @param content - tool result content blocks.
   * @returns the scrubbed blocks, or the same array when nothing matched.
   */
  scrubContent(content) {
    if (this.secrets.length === 0 || !Array.isArray(content)) return content
    let changed = false
    const next = content.map((block) => {
      if (block?.type !== 'text' || typeof block.text !== 'string') return block
      const text = this.scrub(block.text)
      if (text === block.text) return block
      changed = true
      return { ...block, text }
    })
    return changed ? next : content
  }
}

/**
 * The encoded forms one secret may take in tool output: verbatim, URL-encoded
 * (upper and lower hex), base64, base64url, hex, and JSON-escaped. Every
 * variant is long enough to be distinctive because the source value is.
 *
 * @param value - the stored token value.
 * @returns the variants, longest-sourced first entry being the value itself.
 */
function scrubVariants(value) {
  const out = [value]
  const url = encodeURIComponent(value)
  if (!out.includes(url)) out.push(url)
  const urlLower = url.replace(/%[0-9A-Fa-f]{2}/g, (part) => part.toLowerCase())
  if (!out.includes(urlLower)) out.push(urlLower)
  const b64 = Buffer.from(value, 'utf8').toString('base64')
  if (b64.length >= MIN_SCRUB_LENGTH && !out.includes(b64)) out.push(b64)
  const b64url = b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  if (b64url.length >= MIN_SCRUB_LENGTH && !out.includes(b64url)) out.push(b64url)
  if (value.length <= MAX_HEX_SCRUB_LENGTH) {
    const hex = Buffer.from(value, 'utf8').toString('hex')
    if (hex.length >= MIN_SCRUB_LENGTH && !out.includes(hex)) out.push(hex)
  }
  if (/[\\"\n\r\t]/.test(value)) {
    const escaped = JSON.stringify(value).slice(1, -1)
    if (!out.includes(escaped)) out.push(escaped)
  }
  return out
}

/** JSON response (no-store: the vault is live user state). */
function sendJson(res, status, payload) {
  res.statusCode = status
  res.setHeader('content-type', 'application/json; charset=utf-8')
  res.setHeader('cache-control', 'no-store')
  res.end(JSON.stringify(payload))
}

/** 405 with the route's one supported method. */
function sendMethodNotAllowed(res, allow) {
  res.statusCode = 405
  res.setHeader('allow', allow)
  res.end()
}

/**
 * Collect a bounded request body as a JSON object; null when it is not one.
 *
 * @param req - the incoming request.
 * @param maxBytes - ceiling for this route (imports are larger than commands).
 */
async function readObjectBody(req, maxBytes = MAX_BODY_BYTES) {
  const chunks = []
  let size = 0
  for await (const chunk of req) {
    size += chunk.byteLength
    if (size > maxBytes) {
      req.resume()
      return null
    }
    chunks.push(chunk)
  }
  const text = Buffer.concat(chunks).toString('utf8').trim()
  if (text === '') return {}
  try {
    const parsed = JSON.parse(text)
    return parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null
  } catch {
    return null
  }
}

/** Tool descriptions for the agent-facing catalogue. */
const TOOL_DESCRIPTION = [
  'List the tokens held by the local token vault (opened from 侧栏 → 令牌库 / Token vault) or ask the user to save a new one.',
  'Values are never returned: the vault only reports each token name, its note, its length and usage metadata.',
  'To use a token, run the command with the `vault_sh` tool: it exports tokens into that command\'s environment,',
  'so the command text says `$GITHUB_TOKEN` and the value never appears in the session, a job record, or a receipt.',
  '`{{token:…}}` placeholders are NOT substituted any more; a `bash` or `run_code` call that contains one is refused.',
  'With action `request-save`, the panel shows a pending entry where the user pastes the value; the agent never handles it.',
].join(' ')

const TOOL_USAGE = [
  'Use a token by running the command with `vault_sh` and referencing the token as an exported environment variable',
  '(for example: vault_sh({ description: "check GitHub identity", command: \'curl -sS -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user\' })).',
  '`vault_sh` accepts `tokens: [NAME]` to export only the named tokens instead of every enabled one.',
  'Other tools (including `write` and `edit`, prompts, and hand-offs) treat a placeholder as inert text, so documentation may spell {{token:NAME}} literally.',
  'Add, change, rename, enable/disable or delete tokens in 侧栏 → 令牌库 (Token vault); the agent can only request a save.',
  'When approval mode is on, the user confirms each command — in the session card or the token vault panel, depending on their setting.',
].join(' ')

export { TokenVault }

export function apply(ctx, config = {}) {
  const file = typeof config.file === 'string' && config.file !== '' ? config.file : defaultFile()
  const auditFile = typeof config.auditFile === 'string' && config.auditFile !== '' ? config.auditFile : defaultAuditFile()
  const projCacheDir = typeof config.projCacheDir === 'string' && config.projCacheDir !== '' ? config.projCacheDir : defaultProjCacheDir()
  const approvalsFile = typeof config.approvalsFile === 'string' && config.approvalsFile !== '' ? config.approvalsFile : defaultApprovalsFile()

  // Session titles for the panel's last-used display, resolved from the same
  // projection cache the GUI reads. Keyed by (mtime, size) so a renamed
  // session re-resolves; capped so a long-lived Host cannot grow it forever.
  const titleCache = new Map()
  const sessionTitleFor = async (sessionId) => {
    if (typeof sessionId !== 'string' || !sessionId.startsWith('session-')) return undefined
    const file = join(projCacheDir, `${sessionId}.json`)
    let info
    try {
      info = await stat(file)
    } catch {
      titleCache.delete(sessionId)
      return undefined
    }
    const key = `${info.mtimeMs}:${info.size}`
    const cached = titleCache.get(sessionId)
    if (cached !== undefined && cached.key === key) return cached.title
    try {
      const parsed = JSON.parse(await readFile(file, 'utf8'))
      const val = parsed?.record?.rows?.title?.val
      const raw = typeof val === 'string' && val.trim() !== ''
        ? val
        : typeof val?.title === 'string' && val.title.trim() !== '' ? val.title : undefined
      let title = raw === undefined ? undefined : raw.trim()
      if (title === undefined) {
        const input = parsed?.record?.rows?.titleInput?.val?.first?.text
        if (typeof input === 'string' && input.trim() !== '') title = input.trim().slice(0, 60)
      }
      if (title === undefined || title === '') return undefined
      if (titleCache.size > 500) titleCache.clear()
      titleCache.set(sessionId, { key, title })
      return title
    } catch {
      return undefined
    }
  }

  /** The value-free catalogue, each entry carrying the environment name it exports and its last-used title. */
  const listWithEnv = async () => {
    const list = vault.list()
    const resolved = await Promise.all(list.map(async (token) => {
      if (token.lastUsedBy === undefined) return token
      const title = await sessionTitleFor(token.lastUsedBy)
      return title === undefined ? token : { ...token, lastUsedBy: title, lastUsedSession: token.lastUsedBy }
    }))
    const envByToken = new Map(vault.environment().exports.map((entry) => [entry.name, entry.env]))
    return resolved.map((token) => ({ ...token, env: envByToken.get(token.name) ?? token.name }))
  }
  const vault = new TokenVault(file, auditFile, ctx.logger)
  // Prompt assembly is synchronous; warm the cache in the background and let a
  // failed read surface on the first route or tool call instead.
  vault.ready().catch((error) => ctx.logger?.warn?.(`token-vault: cannot read ${file}: ${String(error)}`))

  // The same standing confinement `bash` resolves for a call: without a
  // sandboxing executor there is no policy at all, and the shell applies none.
  const sandboxPolicy = ctx.shell.sandboxMode === undefined ? undefined : ctx.get('sandboxPolicy')

  /** Resolve this call's sandbox policy from the owning Session, exactly like `bash`. */
  const resolveSandboxPolicy = (exec) => {
    const session = exec.agent?.session
    return sandboxPolicy?.resolve(session === undefined ? {} : { session })
  }

  /** The state payload every panel refresh starts from. */
  const listPayload = async () => {
    // Surface the pre-encryption backup while it still exists so the panel can
    // keep offering to delete it, even after a page reload.
    const backupPath = `${file}.pre-encryption.bak`
    let backupExists = false
    try {
      await stat(backupPath)
      backupExists = true
    } catch {
      backupExists = false
    }
    return {
      tokens: await listWithEnv(),
      encrypted: vault.encrypted,
      locked: vault.locked,
      backupPath: backupExists ? backupPath : undefined,
      settings: { requireApproval: vault.settings.requireApproval, audit: vault.settings.audit, approvalUI: vault.settings.approvalUI },
    }
  }

  /** Pending user confirmations: agent save requests and vault_sh approvals. */
  const pendings = new Map()

  /** Recent approval outcomes, newest first, for the panel's history view. */
  const approvalHistory = []
  const APPROVAL_DECISIONS = new Set(['approved', 'denied', 'timeout', 'aborted'])

  /** Serialized writes keep concurrent records from interleaving. */
  let approvalWriting = Promise.resolve()

  /** Load the persisted history once; ENOENT simply means "no records yet". */
  const approvalHistoryLoaded = (async () => {
    try {
      const text = await readFile(approvalsFile, 'utf8')
      const parsed = JSON.parse(text)
      const list = Array.isArray(parsed?.entries) ? parsed.entries : []
      for (const raw of list) {
        if (raw === null || typeof raw !== 'object' || !APPROVAL_DECISIONS.has(raw.decision)) continue
        approvalHistory.push({
          id: typeof raw.id === 'string' && raw.id !== '' ? raw.id : randomUUID(),
          at: typeof raw.at === 'string' ? raw.at : new Date().toISOString(),
          decision: raw.decision,
          ui: raw.ui === 'session' ? 'session' : 'panel',
          sessionTitle: typeof raw.sessionTitle === 'string' && raw.sessionTitle !== '' ? raw.sessionTitle : undefined,
          tokens: Array.isArray(raw.tokens) ? raw.tokens.filter((token) => typeof token === 'string') : [],
          description: typeof raw.description === 'string' ? raw.description : '',
        })
        if (approvalHistory.length >= 50) break
      }
    } catch (error) {
      if (error?.code !== 'ENOENT') ctx.logger?.warn?.(`token-vault: cannot read ${approvalsFile}: ${String(error)}`)
    }
  })()

  /** Persist the current list (atomic, 0600). Failures only warn. */
  const persistApprovalHistory = () => {
    approvalWriting = approvalWriting
      .then(() => approvalHistoryLoaded)
      .then(async () => {
        await mkdir(dirname(approvalsFile), { recursive: true })
        const temporary = `${approvalsFile}.${process.pid}.tmp`
        const payload = `${JSON.stringify({ version: 1, entries: approvalHistory }, null, 2)}\n`
        await writeFile(temporary, payload, { encoding: 'utf8', mode: 0o600 })
        await rename(temporary, approvalsFile)
      })
      .catch((error) => {
        ctx.logger?.warn?.(`token-vault: cannot persist the approval history: ${String(error)}`)
      })
  }

  /**
   * Record one approval outcome (newest first, capped at 50) and persist it.
   * `payload` carries tokens/description/sessionTitle — never values or commands.
   */
  const recordApproval = (decision, ui, payload) => {
    approvalHistory.unshift({
      id: randomUUID(),
      at: new Date().toISOString(),
      decision,
      ui,
      sessionTitle: payload.sessionTitle,
      tokens: payload.tokens ?? [],
      description: payload.description ?? '',
    })
    if (approvalHistory.length > 50) approvalHistory.length = 50
    persistApprovalHistory()
  }

  /** Register one pending confirmation; returns its handle. */
  const addPending = (type, payload) => {
    if (pendings.size >= MAX_PENDING) {
      throw new VaultError('待确认事项太多，请先在令牌库面板处理或清除它们')
    }
    const id = randomUUID()
    const entry = { id, type, requestedAt: new Date().toISOString(), payload }
    pendings.set(id, entry)
    return entry
  }

  /** Serialize the pending list for the panel (values never appear here). */
  const pendingPayload = () => {
    const nowMs = Date.now()
    for (const entry of [...pendings.values()]) {
      if (entry.type !== 'sh') continue
      const age = nowMs - new Date(entry.requestedAt).getTime()
      // A little grace over the approval window so the real timer wins races.
      if (age > APPROVAL_TIMEOUT_MS + 5000) pendings.delete(entry.id)
    }
    const requests = []
    const approvals = []
    const envByToken = new Map(vault.environment().exports.map((entry) => [entry.name, entry.env]))
    for (const entry of pendings.values()) {
      if (entry.type === 'save') {
        requests.push({
          id: entry.id,
          type: 'save',
          name: entry.payload.name,
          note: entry.payload.note ?? '',
          source: entry.payload.source ?? '',
          sessionTitle: entry.payload.sessionTitle,
          requestedAt: entry.requestedAt,
        })
      } else {
        approvals.push({
          id: entry.id,
          type: 'sh',
          description: entry.payload.description ?? '',
          command: entry.payload.command ?? '',
          tokens: entry.payload.tokens ?? [],
          tokenEnvs: (entry.payload.tokens ?? []).map((name) => envByToken.get(name) ?? name),
          sessionTitle: entry.payload.sessionTitle,
          expiresAt: new Date(new Date(entry.requestedAt).getTime() + APPROVAL_TIMEOUT_MS).toISOString(),
          requestedAt: entry.requestedAt,
        })
      }
    }
    return { requests, approvals }
  }

  /**
   * Wait for the user's approval of one `vault_sh` command.
   *
   * @param payload - the command description and text (value-free by design).
   * @param signal - the tool call's abort signal.
   * @returns when approved; rejects when denied, timed out or aborted.
   */
  const awaitApproval = (payload, signal) =>
    new Promise((resolve, reject) => {
      const entry = addPending('sh', payload)
      const onAbort = () => entry.deny('工具调用已中止')
      const cleanup = () => {
        clearTimeout(entry.timer)
        pendings.delete(entry.id)
        if (signal !== undefined) signal.removeEventListener('abort', onAbort)
      }
      entry.approve = () => {
        cleanup()
        resolve()
      }
      entry.deny = (reason) => {
        cleanup()
        reject(new VaultError(reason))
      }
      entry.timer = setTimeout(() => {
        cleanup()
        recordApproval('timeout', 'panel', payload)
        reject(new VaultError(`审批超时（${Math.round(APPROVAL_TIMEOUT_MS / 1000)} 秒）：命令没有执行 —— 请在令牌库面板批准，或在那里把审批模式关掉`))
      }, APPROVAL_TIMEOUT_MS)
      if (signal !== undefined) {
        signal.addEventListener('abort', () => {
          recordApproval('aborted', 'panel', payload)
          onAbort()
        }, { once: true })
      }
    })

  /** Answer an untrusted/unauthenticated request; true when it was rejected. */
  const rejected = (req, res) => {
    const rejection = ctx.connection.requestRejection(req)
    if (rejection === undefined) return false
    res.statusCode = rejection
    res.end()
    return true
  }

  /** One response envelope: `{ ok, …payload }`. */
  const operationResult = (payload) => (payload === undefined ? { ok: true } : { ok: true, ...payload })

  /** Run one panel operation, mapping a VaultError to its user-facing 400. */
  const respond = async (res, operation) => {
    try {
      sendJson(res, 200, operationResult(await operation()))
    } catch (error) {
      if (error instanceof VaultError) {
        sendJson(res, 400, { message: error.message })
        return
      }
      ctx.logger?.warn?.(`token-vault: ${String(error)}`)
      sendJson(res, 500, { message: '令牌库无法完成这个操作' })
    }
  }

  /** Validate the name field shared by most routes. */
  const readName = (body, field = 'name') => {
    const value = typeof body?.[field] === 'string' ? body[field] : ''
    if (!NAME_PATTERN.test(value)) {
      throw new VaultError('名称要以字母或下划线开头，只能包含字母、数字、点、横线或下划线')
    }
    return value
  }

  /** POST-only route helper. */
  const route = (path, label, handler) => {
    ctx.effect(
      () =>
        ctx.webServer.register({
          kind: 'exact',
          path,
          handler: async (req, res) => {
            if (rejected(req, res)) return
            if (req.method !== 'POST') {
              sendMethodNotAllowed(res, 'POST')
              return
            }
            const body = await readObjectBody(req, path === IMPORT_PATH || path === IMPORT_ENV_PATH ? MAX_IMPORT_BYTES : MAX_BODY_BYTES)
            if (body === null) {
              sendJson(res, 400, { message: '请求内容必须是 JSON 对象（或者文件太大）' })
              return
            }
            await respond(res, () => handler(body))
          },
        }),
      label,
    )
  }

  // GET the value-free catalogue plus the vault's security state.
  ctx.effect(
    () =>
      ctx.webServer.register({
        kind: 'exact',
        path: LIST_PATH,
        handler: async (req, res) => {
          if (rejected(req, res)) return
          if (req.method !== 'GET') {
            sendMethodNotAllowed(res, 'GET')
            return
          }
          await respond(res, async () => {
            await vault.ready()
            return listPayload()
          })
        },
      }),
    `token-vault: GET ${LIST_PATH}`,
  )

  // POST create or update one token (fields may be omitted to keep current ones).
  route(SAVE_PATH, `token-vault: POST ${SAVE_PATH}`, async (body) => {
    const tokenName = readName(body)
    if (body.value !== undefined && typeof body.value !== 'string') throw new VaultError('令牌值必须是文本')
    if (body.note !== undefined && typeof body.note !== 'string') throw new VaultError('备注必须是文本')
    if (body.enabled !== undefined && typeof body.enabled !== 'boolean') throw new VaultError('启用开关的取值不合法')
    const result = await vault.save({
      name: tokenName,
      ...body.value === undefined ? {} : { value: body.value },
      ...body.note === undefined ? {} : { note: body.note },
      ...body.enabled === undefined ? {} : { enabled: body.enabled },
      ...body.expiresAt === undefined ? {} : { expiresAt: body.expiresAt },
      ...body.checkUrl === undefined ? {} : { checkUrl: body.checkUrl },
      ...body.checkHeader === undefined ? {} : { checkHeader: body.checkHeader },
    })
    if (result.duplicateOf.length > 0) {
      await vault.audit({ kind: 'save-duplicate-warning', token: tokenName, duplicates: result.duplicateOf })
    }
    const envByToken = new Map(vault.environment().exports.map((entry) => [entry.name, entry.env]))
    return { token: { ...result.token, env: envByToken.get(result.token.name) }, duplicateOf: result.duplicateOf, ...(await listPayload()) }
  })

  // POST delete one token.
  route(DELETE_PATH, `token-vault: POST ${DELETE_PATH}`, async (body) => {
    const tokenName = readName(body)
    await vault.remove(tokenName)
    return { tokens: await listWithEnv() }
  })

  // POST rename one token, keeping value and history.
  route(RENAME_PATH, `token-vault: POST ${RENAME_PATH}`, async (body) => {
    const from = readName(body, 'from')
    const to = readName(body, 'to')
    const token = await vault.rename(from, to)
    return { token, ...(await listPayload()) }
  })

  // POST export: the one route that returns values. It exists for the panel's
  // explicit export action; an optional password encrypts the download, and a
  // plain export additionally requires the typed confirmation, so a stray
  // same-origin script cannot silently walk the vault out of the browser.
  route(EXPORT_PATH, `token-vault: POST ${EXPORT_PATH}`, async (body) => {
    const password = typeof body.password === 'string' ? body.password : ''
    if (password.length > MAX_PASSWORD_LENGTH) throw new VaultError(`密码最多 ${MAX_PASSWORD_LENGTH} 个字符`)
    await vault.ready()
    if (password === '') {
      if (body.confirm !== EXPORT_CONFIRMATION) {
        throw new VaultError(`明文导出需要在确认框里输入「${EXPORT_CONFIRMATION}」`)
      }
    }
    const tokens = vault.exportAll()
    await vault.audit({ kind: 'export', count: tokens.length, encrypted: password !== '' })
    const document = {
      format: EXPORT_FORMAT,
      version: EXPORT_VERSION,
      exportedAt: new Date().toISOString(),
      tokens,
    }
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
    if (password === '') {
      return {
        encrypted: false,
        count: tokens.length,
        filename: `token-vault-${stamp}.json`,
        payload: `${JSON.stringify(document, null, 2)}\n`,
      }
    }
    return {
      encrypted: true,
      count: tokens.length,
      filename: `token-vault-${stamp}.tvault`,
      payload: `${JSON.stringify(await encryptExport(document, password), null, 2)}\n`,
    }
  })

  // POST import: merge a previously exported file (plaintext or encrypted).
  route(IMPORT_PATH, `token-vault: POST ${IMPORT_PATH}`, async (body) => {
    const payload = typeof body.payload === 'string' ? body.payload : ''
    if (payload.trim() === '') throw new VaultError('文件是空的')
    let parsed
    try {
      parsed = JSON.parse(payload)
    } catch {
      throw new VaultError('文件不是合法的 JSON')
    }
    const password = typeof body.password === 'string' ? body.password : ''
    if (password.length > MAX_PASSWORD_LENGTH) throw new VaultError(`密码最多 ${MAX_PASSWORD_LENGTH} 个字符`)
    const mode = body.mode === 'overwrite' ? 'overwrite' : 'merge'
    const document = parsed !== null && typeof parsed === 'object' && parsed.encrypted === true
      ? await decryptExport(parsed, password)
      : parsed
    const entries = parseImportDocument(document)
    const result = await vault.importEntries(entries, mode)
    await vault.audit({ kind: 'import', ...result, mode })
    return { ...result, ...(await listPayload()) }
  })

  // POST import-env: the client parses a .env file and sends ready entries.
  route(IMPORT_ENV_PATH, `token-vault: POST ${IMPORT_ENV_PATH}`, async (body) => {
    const list = Array.isArray(body.entries) ? body.entries : []
    if (list.length === 0) throw new VaultError('没有可导入的条目')
    if (list.length > MAX_IMPORT_TOKENS) throw new VaultError(`条目超过 ${MAX_IMPORT_TOKENS} 条`)
    const entries = []
    const rejectedNames = []
    for (const raw of list) {
      const entry = coerceEntry(raw)
      if (entry === undefined) {
        rejectedNames.push(typeof raw?.name === 'string' && raw.name !== '' ? raw.name : '(unnamed)')
        continue
      }
      entries.push(entry)
    }
    const mode = body.mode === 'overwrite' ? 'overwrite' : 'merge'
    const result = entries.length === 0 ? { added: [], updated: [], skipped: [] } : await vault.importEntries(entries, mode)
    await vault.audit({ kind: 'import-env', ...result, rejected: rejectedNames.length, mode })
    return { ...result, rejected: rejectedNames, ...(await listPayload()) }
  })

  // POST settings: the panel's approval-mode and audit toggles.
  route(SETTINGS_PATH, `token-vault: POST ${SETTINGS_PATH}`, async (body) => {
    await vault.ready()
    vault.requireUnlocked()
    let changed = false
    if (typeof body.requireApproval === 'boolean') {
      vault.settings.requireApproval = body.requireApproval
      changed = true
    }
    if (typeof body.audit === 'boolean') {
      vault.settings.audit = body.audit
      changed = true
    }
    if (body.approvalUI === 'session' || body.approvalUI === 'panel') {
      vault.settings.approvalUI = body.approvalUI
      changed = true
    }
    if (changed) await vault.flush()
    return listPayload()
  })

  // POST encrypt: enable at-rest encryption (or change the master password).
  route(ENCRYPT_PATH, `token-vault: POST ${ENCRYPT_PATH}`, async (body) => {
    const password = typeof body.password === 'string' ? body.password : ''
    const result = await vault.enableEncryption(password)
    return { ...(await listPayload()), ...result }
  })

  // POST disable-encryption: back to a plaintext document after verifying the password.
  route(DISABLE_ENCRYPTION_PATH, `token-vault: POST ${DISABLE_ENCRYPTION_PATH}`, async (body) => {
    const password = typeof body.password === 'string' ? body.password : ''
    await vault.disableEncryption(password)
    return listPayload()
  })

  // POST unlock: open an encrypted vault for this Host boot.
  route(UNLOCK_PATH, `token-vault: POST ${UNLOCK_PATH}`, async (body) => {
    await vault.unlock(typeof body.password === 'string' ? body.password : '')
    return listPayload()
  })

  // POST lock: forget values and the key until the next unlock.
  route(LOCK_PATH, `token-vault: POST ${LOCK_PATH}`, async () => {
    await vault.ready()
    vault.lock()
    return listPayload()
  })

  // POST delete-backup: remove the plaintext backup left by enabling encryption.
  route(DELETE_BACKUP_PATH, `token-vault: POST ${DELETE_BACKUP_PATH}`, async () => {
    await vault.ready()
    const backupPath = `${file}.pre-encryption.bak`
    try {
      await unlink(backupPath)
      return { deleted: true, backupPath }
    } catch (error) {
      if (error?.code === 'ENOENT') return { deleted: false, backupPath }
      throw new VaultError('备份文件删不掉')
    }
  })

  // GET the recent approval outcomes for the panel's history view. This list
  // never carries command text or values — decisions, sources and metadata only.
  ctx.effect(
    () =>
      ctx.webServer.register({
        kind: 'exact',
        path: HISTORY_PATH,
        handler: async (req, res) => {
          if (rejected(req, res)) return
          if (req.method !== 'GET') {
            sendMethodNotAllowed(res, 'GET')
            return
          }
          await respond(res, async () => {
            await approvalHistoryLoaded
            return ({
            history: approvalHistory.map((entry) => ({
              id: entry.id,
              at: entry.at,
              decision: entry.decision,
              ui: entry.ui,
              sessionTitle: entry.sessionTitle,
              tokens: entry.tokens,
              description: entry.description,
            })),
            })
          })
        },
      }),
    `token-vault: GET ${HISTORY_PATH}`,
  )

  // POST clear: remove every approval record (the user's explicit action).
  route(HISTORY_CLEAR_PATH, `token-vault: POST ${HISTORY_CLEAR_PATH}`, async () => {
    await approvalHistoryLoaded
    approvalHistory.length = 0
    await persistApprovalHistory()
    await approvalWriting
    return { cleared: true }
  })

  // POST delete: remove one approval record by id.
  route(HISTORY_DELETE_PATH, `token-vault: POST ${HISTORY_DELETE_PATH}`, async (body) => {
    await approvalHistoryLoaded
    const id = typeof body.id === 'string' ? body.id : ''
    const index = approvalHistory.findIndex((entry) => entry.id === id)
    if (index < 0) throw new VaultError('找不到这条审批记录（可能已被删除）')
    approvalHistory.splice(index, 1)
    await persistApprovalHistory()
    await approvalWriting
    return { deleted: id }
  })

  // GET the pending confirmations (agent save requests and command approvals).
  ctx.effect(
    () =>
      ctx.webServer.register({
        kind: 'exact',
        path: PENDING_PATH,
        handler: async (req, res) => {
          if (rejected(req, res)) return
          if (req.method !== 'GET') {
            sendMethodNotAllowed(res, 'GET')
            return
          }
          await respond(res, async () => pendingPayload())
        },
      }),
    `token-vault: GET ${PENDING_PATH}`,
  )

  // POST resolve: approve or deny one pending confirmation.
  route(RESOLVE_PATH, `token-vault: POST ${RESOLVE_PATH}`, async (body) => {
    const id = typeof body.id === 'string' ? body.id : ''
    const entry = pendings.get(id)
    if (entry === undefined) throw new VaultError('找不到这个待确认请求（可能已经处理过了）')
    const decision = body.decision === 'approve' ? 'approve' : 'deny'
    if (entry.type === 'sh') {
      if (decision === 'approve') {
        recordApproval('approved', 'panel', entry.payload)
        entry.approve()
        return { resolved: id }
      }
      recordApproval('denied', 'panel', entry.payload)
      entry.deny('你在令牌库面板里拒绝了这条命令，命令没有执行')
      return { resolved: id }
    }
    // A save request: approving writes the token the user just filled in.
    if (decision !== 'approve') {
      pendings.delete(id)
      return { resolved: id, saved: false }
    }
    const tokenName = readName(entry.payload, 'name')
    const value = typeof body.value === 'string' ? body.value : ''
    if (value === '') throw new VaultError('要完成这个保存请求，需要填写令牌值')
    // Keep the entry until the save actually succeeds: a typo or an oversize
    // value should leave the card in place for another try.
    const result = await vault.save({
      name: tokenName,
      value,
      ...body.note === undefined && entry.payload.note === undefined ? {} : { note: typeof body.note === 'string' ? body.note : entry.payload.note },
    })
    pendings.delete(id)
    await vault.audit({ kind: 'save-request-completed', token: tokenName })
    return { resolved: id, saved: true, token: result.token, duplicateOf: result.duplicateOf, ...(await listPayload()) }
  })

  // POST check: run the health check URL of one token and report the status code.
  route(CHECK_PATH, `token-vault: POST ${CHECK_PATH}`, async (body) => {
    await vault.ready()
    vault.requireUnlocked()
    const tokenName = readName(body)
    const entry = vault.tokens.get(tokenName)
    if (entry === undefined) throw new VaultError(`没有叫「${tokenName}」的令牌`)
    // Defense in depth: the load path already drops invalid fields, but the
    // command below interpolates these values into a shell line, so re-check.
    let url
    let header
    try {
      url = normalizeCheckUrl(entry.checkUrl)
      header = normalizeCheckHeader(entry.checkHeader)
    } catch {
      throw new VaultError(`「${tokenName}」的检查设置不合法 —— 请在面板里重新设置检查 URL 和请求头`)
    }
    if (url === undefined) {
      // Fall back to the built-in endpoint of a well-known provider so the
      // panel's test button works before the user configures anything.
      const fallback = defaultCheck(tokenName)
      if (fallback === undefined) {
        throw new VaultError(`没有给「${tokenName}」设置检查 URL —— 请先在面板里设置（GitHub、GitLab、Hugging Face、Slack、Cloudflare 这类令牌名有内置默认值）`)
      }
      url = fallback.url
      header = fallback.header
    }
    // A token with a check URL but no custom header (the panel's normal case)
    // must still send the default bearer template — never the literal text
    // "undefined".
    header = header ?? DEFAULT_CHECK_HEADER
    const command = `curl -sS -o /dev/null -m 10 -w '%{http_code}' -H "${header}" "${url}"`
    const spec = ctx.shell.resolve({
      command,
      env: { [CHECK_ENV]: entry.value },
      timeoutMs: 15_000,
    })
    let status = 0
    try {
      const result = await (await ctx.shell.execute(spec)).result()
      status = Number.parseInt(result.stdout.text.trim(), 10)
      if (!Number.isInteger(status)) status = 0
    } catch (error) {
      ctx.logger?.warn?.(`token-vault: check for "${tokenName}" failed: ${String(error)}`)
    }
    await vault.audit({ kind: 'check', token: tokenName, status })
    return { status, ok: status >= 200 && status < 300, unauthorized: status === 401 || status === 403 }
  })

  // Refuse placeholder references in the tools that execute a string. Nothing
  // substitutes them any more — a substituted command line ends up verbatim in a
  // durable `job/registered` label and comes back through job receipts — so a
  // reference there is a usage error with the correct instruction attached.
  ctx.effect(
    () =>
      ctx.on('tools/pre-execute', async (exec, next) => {
        if (!PLACEHOLDER_GUARDED.has(exec.name)) return next()
        const referenced = vault.references(exec.arguments)
        if (referenced.length === 0) return next()
        const exported = vault.environment().exports.map((entry) => `$${entry.env}`)
        return {
          kind: 'deny',
          reason: [
            `token placeholders are not substituted into tool arguments: ${referenced.map((entry) => `{{token:${entry}}}`).join(', ')}.`,
            exported.length > 0
              ? `Run the command with \`${SHELL_TOOL_NAME}\` instead, where the vault exports the token as an environment variable: ${exported.join(', ')}.`
              : 'The token vault is empty or locked; the user manages tokens in 侧栏 → 令牌库 (Token vault).',
            'A substituted command line would be recorded verbatim in the job log and could leak the value.',
          ].join(' '),
        }
      }),
    'token-vault: placeholder guard',
  )

  // Scrub stored values out of tool output so an echoing command cannot leak one.
  // Registered exactly once — a second registration made the hook chain run twice.
  ctx.effect(
    () =>
      ctx.on('tools/post-execute', async (exec, result, next) => {
        const decision = await next()
        if (decision.kind !== 'accept') return decision
        const content = vault.scrubContent(decision.content ?? result.content)
        const contexts = Array.isArray(decision.additionalContexts)
          ? decision.additionalContexts.map((context) => {
              if (typeof context === 'string') return vault.scrub(context)
              if (context !== null && typeof context === 'object' && typeof context.text === 'string') {
                return { ...context, text: vault.scrub(context.text) }
              }
              return context
            })
          : decision.additionalContexts
        const contentChanged = content !== (decision.content ?? result.content)
        const contextsChanged = Array.isArray(decision.additionalContexts) && contexts.some((context, index) => context !== decision.additionalContexts[index])
        if (!contentChanged && !contextsChanged) return decision
        return {
          kind: 'accept',
          content,
          ...contexts === undefined ? {} : { additionalContexts: contexts },
        }
      }),
    'token-vault: result scrub',
  )

  ctx.effect(
    () =>
      ctx.tools.register({
        name: TOOL_NAME,
        description: TOOL_DESCRIPTION,
        parameters: {
          type: 'object',
          additionalProperties: false,
          properties: {
            action: {
              type: 'string',
              enum: ['list', 'request-save'],
              description: '`list` returns token names, notes, lengths and usage metadata (never values). `request-save` asks the user to store a token: the panel shows a pending entry where the user pastes the value.',
            },
            name: {
              type: 'string',
              description: 'With `request-save`: the token name to store, e.g. GITHUB_TOKEN. Ignored by `list`.',
            },
            note: {
              type: 'string',
              description: 'With `request-save`: what the token is for (shown to the user). Ignored by `list`.',
            },
            source: {
              type: 'string',
              description: 'With `request-save`: why the token is needed / where it comes from, one short line. Ignored by `list`.',
            },
          },
        },
        output: {
          schema: {
            type: 'object',
            additionalProperties: false,
            required: ['usage'],
            properties: {
              tokens: {
                type: 'array',
                items: {
                  type: 'object',
                  additionalProperties: false,
                  required: ['name', 'note', 'length', 'env', 'enabled'],
                  properties: {
                    name: { type: 'string' },
                    note: { type: 'string' },
                    length: { type: 'number' },
                    env: { type: 'string' },
                    enabled: { type: 'boolean' },
                    lastUsedAt: { type: 'string' },
                    lastUsedBy: { type: 'string' },
                    lastUsedSession: { type: 'string' },
                    expiresAt: { type: 'string' },
                    checkUrl: { type: 'string' },
                  },
                },
              },
              requested: { type: 'boolean' },
              message: { type: 'string' },
              locked: { type: 'boolean' },
              usage: { type: 'string' },
            },
          },
          render(_args, value) {
            const lines = []
            if (value.requested === true) {
              lines.push(value.message ?? 'The save request was sent to the panel.')
            } else if (value.locked === true) {
              lines.push('The token vault is locked (encrypted at rest); the user must unlock it in 侧栏 → 令牌库 (Token vault).')
            } else if (value.tokens === undefined || value.tokens.length === 0) {
              lines.push('The local token vault is empty.')
            } else {
              lines.push(`Stored tokens (values hidden, ${value.tokens.length}):`)
              for (const token of value.tokens) {
                const note = token.note === '' ? '' : ` — ${token.note}`
                const state = token.enabled ? '' : ' [disabled]'
                lines.push(`- ${token.name}${note} (${token.length} characters) → $${token.env}${state}`)
              }
            }
            lines.push('', value.usage)
            return [{ type: 'text', text: lines.join('\n') }]
          },
        },
        async execute(args, exec) {
          await vault.ready()
          const action = args?.action === 'request-save' ? 'request-save' : 'list'
          if (action === 'list') {
            if (vault.locked) {
              return { locked: true, usage: TOOL_USAGE }
            }
            return {
              tokens: (await listWithEnv()).map((token) => ({
                name: token.name,
                note: token.note,
                length: token.length,
                env: token.env,
                enabled: token.enabled,
                ...(token.lastUsedAt === undefined ? {} : { lastUsedAt: token.lastUsedAt }),
                ...(token.lastUsedBy === undefined ? {} : { lastUsedBy: token.lastUsedBy }),
                ...(token.lastUsedSession === undefined ? {} : { lastUsedSession: token.lastUsedSession }),
                ...(token.expiresAt === undefined ? {} : { expiresAt: token.expiresAt }),
                ...(token.checkUrl === undefined ? {} : { checkUrl: token.checkUrl }),
              })),
              usage: TOOL_USAGE,
            }
          }
          // request-save: the agent never supplies the value.
          const tokenName = readName(args ?? {}, 'name')
          if (RESERVED_ENV_NAMES.has(tokenName)) {
            throw new VaultError(`「${tokenName}」是系统保留的变量名，不能作为令牌名`)
          }
          const note = typeof args.note === 'string' ? args.note.slice(0, MAX_NOTE_LENGTH) : ''
          const source = typeof args.source === 'string' ? args.source.slice(0, MAX_SOURCE_LENGTH) : ''
          await vault.ready()
          vault.requireUnlocked()
          const sessionTitle = await sessionTitleFor(exec?.agent?.id ?? '')
          addPending('save', { name: tokenName, note, source, sessionTitle })
          await vault.audit({ kind: 'save-request', token: tokenName })
          return {
            requested: true,
            message: `The save request for "${tokenName}" was sent to the token vault panel: the user pastes the value there and confirms. The token appears in \`token_vault\` list once saved.`,
            usage: TOOL_USAGE,
          }
        },
      }),
    'token-vault: tool',
  )

  // The only path a token takes into a command: the child process environment.
  // The command text names variables, never values, so the session log, the job
  // label, and every receipt stay clean even for long or background-ish work.
  ctx.effect(
    () =>
      ctx.tools.register({
        name: SHELL_TOOL_NAME,
        description: [
          'Run a bash command with the local token vault\'s tokens exported as environment variables.',
          'Reference them as `$NAME` (double quotes or unquoted — single quotes do not expand).',
          'Pass `tokens: [NAME]` to export only the named tokens (default: every enabled token).',
          'The value never appears in the command text, the session log, or a job record; tool output is scrubbed if a command echoes one.',
          'The command runs under the same sandbox policy, working directory and DSH_* environment as `bash`.',
          '`run_in_background: true` returns a job id immediately (collect with job_output, stop with job_kill; no timeout applies).',
          'Use this instead of `bash` whenever a command needs a stored token; `{{token:…}}` placeholders are refused.',
        ].join(' '),
        parameters: {
          type: 'object',
          additionalProperties: false,
          required: ['description', 'command'],
          properties: {
            description: {
              type: 'string',
              description: 'Clear, concise description of what this command does in active voice, 5-10 words (shown in the UI). Write it in the language the user is speaking (中文用户就写中文) — the approval card shows this line to the user.',
            },
            command: {
              type: 'string',
              description: 'The bash command, referring to tokens as environment variables such as $GITHUB_TOKEN.',
            },
            tokens: {
              type: 'array',
              items: { type: 'string' },
              description: 'Export only these token names into the environment; omit to export every enabled token.',
            },
            workdir: {
              type: 'string',
              description: 'Working directory. Defaults to the session workspace; a relative path is resolved against it.',
            },
            timeoutMs: {
              type: 'number',
              description: 'Timeout in milliseconds (foreground only); the executor applies its configured default and cap and kills the command on expiry.',
            },
            run_in_background: {
              type: 'boolean',
              description: 'Run in the background and return a job id immediately (collect with job_output, stop with job_kill). No timeout applies.',
            },
          },
        },
        output: {
          schema: {
            oneOf: [
              {
                type: 'object',
                additionalProperties: false,
                required: ['kind', 'jobId', 'cwd', 'exports'],
                properties: {
                  kind: { type: 'string', const: 'background' },
                  jobId: { type: 'string' },
                  cwd: { type: 'string' },
                  exports: {
                    type: 'array',
                    items: {
                      type: 'object',
                      additionalProperties: false,
                      required: ['name', 'env', 'length'],
                      properties: {
                        name: { type: 'string' },
                        env: { type: 'string' },
                        length: { type: 'number' },
                      },
                    },
                  },
                },
              },
              {
                type: 'object',
                additionalProperties: false,
                required: ['kind', 'cwd', 'exitCode', 'signal', 'timedOut', 'aborted', 'stdout', 'stderr', 'exports'],
                properties: {
                  kind: { type: 'string', const: 'foreground' },
                  cwd: { type: 'string' },
                  exitCode: { oneOf: [{ type: 'number' }, { type: 'null' }] },
                  signal: { oneOf: [{ type: 'string' }, { type: 'null' }] },
                  timedOut: { type: 'boolean' },
                  aborted: { type: 'boolean' },
                  stdout: {
                    type: 'object',
                    additionalProperties: false,
                    required: ['text', 'truncated'],
                    properties: {
                      text: { type: 'string' },
                      truncated: { type: 'boolean' },
                      spillPath: { type: 'string' },
                    },
                  },
                  stderr: {
                    type: 'object',
                    additionalProperties: false,
                    required: ['text', 'truncated'],
                    properties: {
                      text: { type: 'string' },
                      truncated: { type: 'boolean' },
                      spillPath: { type: 'string' },
                    },
                  },
                  exports: {
                    type: 'array',
                    items: {
                      type: 'object',
                      additionalProperties: false,
                      required: ['name', 'env', 'length'],
                      properties: {
                        name: { type: 'string' },
                        env: { type: 'string' },
                        length: { type: 'number' },
                      },
                    },
                  },
                  sandbox: {
                    type: 'object',
                    additionalProperties: false,
                    required: ['mode', 'denied'],
                    properties: {
                      mode: { type: 'string' },
                      denied: { type: 'boolean' },
                      enforcement: { type: 'string' },
                      runnerFailed: { type: 'boolean' },
                    },
                  },
                },
              },
            ],
          },
          render(_args, value) {
            const exported = value.exports.length === 0
              ? 'tokens exported: none (the vault is empty or locked)'
              : `tokens exported: ${value.exports.map((entry) => `${entry.name} → $${entry.env}`).join(', ')}`
            if (value.kind === 'background') {
              return [{ type: 'text', text: [exported, `started background job ${value.jobId}`, `cwd: ${value.cwd}`].join('\n') }]
            }
            const status = [
              `[exit code: ${value.exitCode === null ? 'none' : value.exitCode}]`,
              value.signal === null ? '' : `[signal: ${value.signal}]`,
              value.timedOut ? '[timed out]' : '',
              value.aborted ? '[aborted]' : '',
              value.sandbox?.denied === true ? `[sandbox: denied under ${value.sandbox.mode} mode]` : '',
            ].filter((part) => part !== '').join(' ')
            const lines = [exported, `cwd: ${value.cwd}`, status]
            const stdout = value.stdout.text.replace(/\n+$/, '')
            const stderr = value.stderr.text.replace(/\n+$/, '')
            if (stdout !== '') lines.push('stdout:', stdout)
            if (stderr !== '') lines.push('stderr:', stderr)
            if (stdout === '' && stderr === '') lines.push('(no output)')
            return [{ type: 'text', text: lines.join('\n') }]
          },
        },
        async execute(args, exec) {
          await vault.ready()
          vault.requireUnlocked()
          // Validate the requested subset before anything runs.
          let onlyNames
          if (args.tokens !== undefined) {
            if (!Array.isArray(args.tokens) || args.tokens.some((name) => typeof name !== 'string' || name === '')) {
              throw new VaultError('tokens 参数必须是令牌名组成的数组')
            }
            const unknown = args.tokens.filter((name) => !vault.tokens.has(name))
            if (unknown.length > 0) {
              const known = vault.list().map((token) => token.name)
              throw new VaultError(`没有这些令牌：${unknown.map((name) => `「${name}」`).join('、')} —— 当前可用：${known.length > 0 ? known.join('、') : '（无）'}`)
            }
            const disabled = args.tokens.filter((name) => vault.tokens.get(name)?.enabled === false)
            if (disabled.length > 0) {
              throw new VaultError(`令牌 ${disabled.map((name) => `「${name}」`).join('、')} 已停用 —— 请在侧栏的令牌库中重新启用`)
            }
            onlyNames = args.tokens
          }
          const { env, exports } = vault.environment(onlyNames)
          const sessionId = exec.agent?.id ?? 'unknown'

          // Approval mode: the user confirms this exact command. Preferred UI
          // is the session's ask_user_question card (right where the user
          // already is); the panel queue remains the fallback and the explicit
          // panel-mode choice. Save requests always stay on the panel because
          // a pasted value must never travel through a logged answer.
          if (vault.settings.requireApproval === true) {
            const sessionTitle = await sessionTitleFor(sessionId)
            const approvalPayload = {
              description: args.description ?? '',
              command: args.command,
              tokens: exports.map((entry) => entry.name),
              sessionTitle,
              session: sessionId,
            }
            const questionsService = exec.agent === undefined ? undefined : ctx.get('userQuestions')
            if (vault.settings.approvalUI === 'session' && questionsService !== undefined && typeof questionsService.ask === 'function') {
              let result
              try {
                result = await questionsService.ask({
                questions: [{
                  id: 'vault-sh-approval',
                  question: approvalBrief(approvalPayload),
                  header: '可以用一下你的令牌吗？',
                  options: [
                    { label: '可以用', description: '把令牌临时借给这条命令，然后执行' },
                    { label: '不行', description: '这条命令不执行，调用直接失败' },
                  ],
                }],
                agent: exec.agent,
                signal: exec.signal,
                ...(exec.callId === undefined ? {} : { wait: { callId: exec.callId } }),
                })
              } catch (askError) {
                // The call died before an answer arrived (aborted, or the
                // question service failed) — record it as an aborted approval.
                recordApproval('aborted', 'session', approvalPayload)
                throw askError
              }
              const approved = Array.isArray(result?.answers) && result.answers.some((answer) => answer.id === 'vault-sh-approval' && Array.isArray(answer.selected) && (answer.selected[0] === '可以用' || answer.selected[0] === '批准'))
              recordApproval(approved ? 'approved' : 'denied', 'session', approvalPayload)
              // An empty selected is an explicit skip — never treated as permission.
              await vault.audit({
                kind: 'sh-approval',
                session: sessionId,
                ui: 'session',
                decision: approved ? 'approved' : 'denied',
                description: args.description ?? '',
                command: args.command,
              })
              if (!approved) {
                throw new VaultError('你在审批卡片里拒绝了或跳过了这条命令，命令没有执行')
              }
            } else {
              await awaitApproval(approvalPayload, exec.signal)
            }
          }

          await vault.touch(exports.map((entry) => entry.name), sessionId)
          await vault.audit({
            kind: 'sh',
            session: sessionId,
            tokens: exports.map((entry) => entry.name),
            description: args.description ?? '',
            command: args.command,
          })

          const cwd = exec.agent === undefined ? undefined : await ctx.workingDirectory.ensure(exec.agent, exec.signal)
          const workdir = resolveWorkdir(args.workdir, cwd)
          const policy = resolveSandboxPolicy(exec)

          if (args.run_in_background === true) {
            const jobs = ctx.get('jobs')
            if (jobs === undefined || typeof jobs.start !== 'function') {
              throw new VaultError('当前部署不支持后台任务，请用前台方式运行 vault_sh')
            }
            if (exec.signal.aborted) throw new VaultError('工具调用已中止')
            const spec = ctx.shell.resolve({
              command: args.command,
              env,
              dshEnv: ctx.shellEnv.collect(exec),
              ...workdir === undefined ? {} : { workdir },
              ...policy === undefined ? {} : { sandboxPolicy: policy },
              onExpiry: 'none',
            })
            const processRef = {}
            const executeSpec = (specWithSignal) => ctx.shell.execute(specWithSignal)
            const jobId = jobs.start({
              kind: SHELL_TOOL_NAME,
              label: args.command,
              ...(exec.callId === undefined ? {} : { toolCall: { callId: exec.callId, rootCallId: exec.rootCallId } }),
              ...(exec.agent?.id === undefined ? {} : { owner: exec.agent.id }),
              output: jobSources(() => processRef.proc),
              run: () => startBackgroundRun(executeSpec, spec, processRef, (proc) => jobOutcome(proc)),
            })
            return { kind: 'background', jobId, cwd: spec.workdir, exports }
          }

          const spec = ctx.shell.resolve({
            command: args.command,
            signal: exec.signal,
            env,
            dshEnv: ctx.shellEnv.collect(exec),
            ...workdir === undefined ? {} : { workdir },
            ...args.timeoutMs === undefined ? {} : { timeoutMs: args.timeoutMs },
            ...policy === undefined ? {} : { sandboxPolicy: policy },
          })
          const result = await (await ctx.shell.execute(spec)).result()
          return {
            kind: 'foreground',
            cwd: spec.workdir,
            exitCode: result.exitCode,
            signal: result.signal,
            timedOut: result.timedOut,
            aborted: result.aborted,
            stdout: {
              text: result.stdout.text,
              truncated: result.stdout.truncated,
              ...result.stdout.spillPath === undefined ? {} : { spillPath: result.stdout.spillPath },
            },
            stderr: {
              text: result.stderr.text,
              truncated: result.stderr.truncated,
              ...result.stderr.spillPath === undefined ? {} : { spillPath: result.stderr.spillPath },
            },
            exports,
            ...result.sandbox === undefined
              ? {}
              : {
                  sandbox: {
                    mode: result.sandbox.mode,
                    denied: result.sandbox.denied,
                    ...result.sandbox.enforcement === undefined ? {} : { enforcement: result.sandbox.enforcement },
                    ...result.sandbox.runnerFailed === undefined ? {} : { runnerFailed: result.sandbox.runnerFailed },
                  },
                },
          }
        },
      }),
    'token-vault: shell tool',
  )

  // Advertise the token names (never values) so every Session can use them
  // without a discovery round trip. `interpolate: false` keeps the documented
  // `$NAME` forms literal instead of letting prompt variables consume them.
  ctx.effect(
    () =>
      ctx.systemPrompt.section({
        name: 'token-vault',
        order: 1950,
        interpolate: false,
        text: () => {
          if (vault.encrypted && vault.locked) {
            return [
              '## Token vault',
              '',
              'The token vault is locked (its stored document is encrypted at rest).',
              'The user unlocks it in 侧栏 → 令牌库 (Token vault); `vault_sh` fails until then.',
            ].join('\n')
          }
          const tokens = vault.list().filter((token) => token.enabled)
          if (tokens.length === 0) return ''
          const envByToken = new Map(vault.environment().exports.map((entry) => [entry.name, entry.env]))
          const rows = tokens.map((token) => {
            const note = token.note === '' ? '' : ` — ${token.note}`
            const expiry = token.expiresAt === undefined ? '' : ` (expires ${token.expiresAt.slice(0, 10)})`
            // The shell variable name is what the model must type; a dotted or
            // dashed token name alone would produce `$my.token-1`, which is not
            // a variable reference at all.
            return `- ${token.name}${note}${expiry} → $${envByToken.get(token.name) ?? token.name}`
          })
          return [
            '## Token vault',
            '',
            'The user keeps these secrets in the local token vault; their values are never shown in this session:',
            ...rows,
            '',
            `Run a command that needs one with \`${SHELL_TOOL_NAME}\`, which exports each token into the child environment:`,
            `  ${SHELL_TOOL_NAME}({ description: "check GitHub identity", command: 'curl -sS -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user' })`,
            'Reference tokens as `$NAME` (double quotes or unquoted). Single quotes do not expand variables.',
            'Pass `tokens: [NAME]` when a command should only receive the named tokens instead of all of them.',
            'Values never enter the command text, so they cannot reach the session log, a job record, or a receipt; tool output is scrubbed if a command echoes one.',
            'Never write `{{token:…}}` inside a `bash` or `run_code` call: placeholders are no longer substituted, and such a call is refused.',
            'Everywhere else (documents, prompts, hand-offs) the placeholder stays inert text, so documentation can spell the syntax.',
            'Adding, changing or deleting a token is the user\'s action in 侧栏 → 令牌库 (Token vault); call the `token_vault` tool to re-list them, or `token_vault({ action: "request-save", name, note })` to ask the user to store one.',
            'With approval mode on, each `vault_sh` call waits for the user\'s confirmation (a session card or the token vault panel, per their setting).',
          ].join('\n')
        },
      }),
    'token-vault: prompt section',
  )
}

/**
 * The output sources one background process publishes to the jobs registry.
 *
 * @param get - the process handle once the starter spawns it.
 * @returns one non-consuming source per stream, stdout first.
 */
function jobSources(get) {
  return ['stdout', 'stderr'].map((channel) => ({
    channel,
    read(fromByte) {
      const live = get()
      const reader = live?.observed?.[channel]
      return reader?.readFrom === undefined ? { text: '', nextOffset: fromByte, lossy: false } : reader.readFrom(fromByte)
    },
  }))
}

/**
 * Start the background run of one resolved command: spawn with job-owned
 * cancellation, wait for settlement, and project the outcome.
 *
 * @param executeSpec - the shell service's execute, called with a spec carrying the job's signal.
 * @param spec - the resolved shell spec (no signal; the job controller supplies one).
 * @param processRef - receives the process handle for the output sources.
 * @param outcome - projects a settled process onto the job outcome.
 * @returns the hooks the registry drives.
 */
function startBackgroundRun(executeSpec, spec, processRef, outcome) {
  const controller = new AbortController()
  let proc
  const done = (async () => {
    try {
      proc = await executeSpec({ ...spec, signal: controller.signal })
      processRef.proc = proc
      try {
        if (controller.signal.aborted) proc.kill()
      } finally {
        await proc.done
      }
      return outcome(proc)
    } catch (error) {
      const killedByCancel = controller.signal.aborted && proc === undefined
      return {
        status: killedByCancel ? 'killed' : 'failed',
        detail: error instanceof Error ? error.message : String(error),
      }
    }
  })()
  return {
    done,
    cancel(reason) {
      if (controller.signal.aborted) return
      controller.abort(reason)
      proc?.kill?.()
    },
  }
}

/**
 * Map a settled process onto the job outcome: nonzero exits are reported, not
 * failed; a sandbox denial joins the detail the roster shows.
 *
 * @param proc - the settled process handle.
 * @returns the registry outcome.
 */
function jobOutcome(proc) {
  const base = proc.status === 'killed'
    ? { status: 'killed', detail: proc.signal !== null && proc.signal !== undefined ? `signal: ${proc.signal}` : 'killed before exit' }
    : { status: 'completed', detail: `exit code: ${proc.exitCode ?? 0}` }
  if (proc.sandbox?.denied === true) {
    return { ...base, detail: `${base.detail}; [sandbox: denied under ${proc.sandbox.mode} mode]` }
  }
  return base
}
