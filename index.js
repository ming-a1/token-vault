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
 * echoes a variable, the value in the output is replaced by {{token:NAME}}.
 *
 * Placeholders are NOT substituted into tool arguments. That design leaked: the
 * jobs registry stores the dispatched command as a job label, so the substituted
 * value landed in a durable `job/registered` event and came back through job
 * receipts. `tools/pre-execute` now refuses placeholder references outright.
 *
 * The value itself is never returned by any route or tool: the panel reads
 * names, notes and value lengths; the agent tools read names and notes.
 *
 * @module @local/token-vault
 */

import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, isAbsolute, join, sep } from 'node:path'

/** Cordis plugin name. */
export const name = 'token-vault'

/** The trust fence, the tool registry, the prompt, and the shell this plugin runs commands through. */
export const inject = ['webServer', 'connection', 'tools', 'systemPrompt', 'shell', 'workingDirectory', 'shellEnv']

/** Accepted token names: a shell-friendly identifier. */
const NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/

/** One `{{token:NAME}}` placeholder occurrence (refused in the tools that execute a string). */
const PLACEHOLDER_PATTERN = /\{\{\s*token\s*:\s*([A-Za-z_][A-Za-z0-9_.-]{0,63})\s*\}\}/g

/** Longest accepted token value. */
const MAX_VALUE_LENGTH = 8192

/** Longest accepted note. */
const MAX_NOTE_LENGTH = 500

/** Request bodies are tiny JSON objects; anything larger is hostile. */
const MAX_BODY_BYTES = 64 * 1024

/** Values shorter than this are never scrubbed — they are too likely to be ordinary text. */
const MIN_SCRUB_LENGTH = 8

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

/** The shell tool: the only way a token reaches a command. */
const SHELL_TOOL_NAME = 'vault_sh'

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

/** The value-free projection every caller may see. */
function publicEntry(entry) {
  return {
    name: entry.name,
    note: entry.note,
    length: entry.value.length,
    createdAt: entry.createdAt,
    updatedAt: entry.updatedAt,
  }
}

/** Normalize one stored record, refusing anything that is not a usable token. */
function normalizeEntry(name, raw, now) {
  const value = typeof raw?.value === 'string' ? raw.value : ''
  return {
    name,
    value,
    note: typeof raw?.note === 'string' ? raw.note : '',
    createdAt: typeof raw?.createdAt === 'string' ? raw.createdAt : now,
    updatedAt: typeof raw?.updatedAt === 'string' ? raw.updatedAt : now,
  }
}

/**
 * The vault: one JSON document, read once, written atomically with owner-only
 * permissions, and mirrored in memory for the placeholder and scrub paths.
 */
class TokenVault {
  tokens = new Map()

  /** Values long enough to scrub, longest first so a prefix never wins over its superstring. */
  secrets = []

  loading

  writing = Promise.resolve()

  /**
   * @param file - absolute path of the JSON document.
   * @param logger - the plugin's logger, for a corrupt-file warning.
   */
  constructor(file, logger) {
    this.file = file
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
    try {
      const parsed = JSON.parse(text)
      const records = parsed?.tokens
      if (records === null || typeof records !== 'object') return
      const now = new Date().toISOString()
      for (const [key, raw] of Object.entries(records)) {
        if (!NAME_PATTERN.test(key)) continue
        const entry = normalizeEntry(key, raw, now)
        if (entry.value === '') continue
        this.tokens.set(key, entry)
      }
    } catch (error) {
      this.logger?.warn?.(`token-vault: ${this.file} is not valid JSON; starting with an empty vault (${String(error)})`)
    }
    this.reindex()
  }

  /** Rebuild the scrub index from the current records. */
  reindex() {
    this.secrets = [...this.tokens.values()]
      .filter((entry) => entry.value.length >= MIN_SCRUB_LENGTH)
      .map((entry) => ({ name: entry.name, value: entry.value, encoded: encodeURIComponent(entry.value) }))
      .sort((left, right) => right.value.length - left.value.length)
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
   * Create or update one record. An omitted `value` keeps the current one; an
   * omitted `note` keeps the current note; a new token needs a value.
   *
   * @param input - validated name, optional value, optional note.
   * @returns the value-free projection of the written record.
   */
  async save(input) {
    await this.ready()
    const existing = this.tokens.get(input.name)
    const value = input.value === undefined ? existing?.value : input.value
    if (value === undefined || value === '') {
      throw new VaultError(`token "${input.name}" does not exist yet — a value is required`)
    }
    if (value.length > MAX_VALUE_LENGTH) throw new VaultError(`the value must be at most ${MAX_VALUE_LENGTH} characters`)
    const note = input.note === undefined ? existing?.note ?? '' : input.note
    if (note.length > MAX_NOTE_LENGTH) throw new VaultError(`the note must be at most ${MAX_NOTE_LENGTH} characters`)
    const now = new Date().toISOString()
    const entry = {
      name: input.name,
      value,
      note,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    }
    this.tokens.set(entry.name, entry)
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
    const removed = this.tokens.delete(tokenName)
    if (!removed) throw new VaultError(`no token named "${tokenName}"`)
    await this.flush()
    this.reindex()
    return true
  }

  /** Write the document atomically: a private temp file in the same directory, then rename. */
  flush() {
    const payload = `${JSON.stringify({ version: 1, tokens: Object.fromEntries(this.tokens) }, null, 2)}\n`
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
   * Export every token into a child environment.
   *
   * Token names allow `.` and `-`, which are not valid in a shell variable, so
   * each name is mapped to a shell-safe one (`.`/`-` become `_`, a leading digit
   * gains a `T_` prefix) and collisions get a numeric suffix.
   *
   * @returns the environment entries and the name mapping the caller reports.
   */
  environment() {
    const taken = new Set()
    const env = {}
    const exports = []
    const entries = [...this.tokens.values()].sort((left, right) => left.name.localeCompare(right.name, 'en'))
    for (const entry of entries) {
      let base = entry.name.replace(/[^A-Za-z0-9_]/g, '_')
      if (!/^[A-Za-z_]/.test(base)) base = `T_${base}`
      let candidate = base
      let suffix = 2
      while (taken.has(candidate)) candidate = `${base}_${suffix++}`
      taken.add(candidate)
      env[candidate] = entry.value
      exports.push({ name: entry.name, env: candidate, length: entry.value.length })
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
      if (out.includes(secret.value)) out = out.split(secret.value).join(`{{token:${secret.name}}}`)
      if (secret.encoded !== secret.value && out.includes(secret.encoded)) {
        out = out.split(secret.encoded).join(`{{token:${secret.name}}}`)
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

/** Collect a bounded request body as a JSON object; null when it is not one. */
async function readObjectBody(req) {
  const chunks = []
  let size = 0
  for await (const chunk of req) {
    size += chunk.byteLength
    if (size > MAX_BODY_BYTES) {
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

/** Resolve a relative per-call workdir against the Session's current directory. */
function resolveWorkdir(modelWorkdir, sessionCwd) {
  if (modelWorkdir === undefined) return sessionCwd
  if (sessionCwd !== undefined && !isAbsolute(modelWorkdir)) return `${sessionCwd}${sep}${modelWorkdir}`
  return modelWorkdir
}

/** The agent-facing tool: names and notes only, never a value. */
const TOOL_NAME = 'token_vault'

const TOOL_DESCRIPTION = [
  'List the tokens held by the local token vault (opened from Settings → 令牌库 / Token vault).',
  'Values are never returned: the vault only reports each token name, its note and its length.',
  'To use a token, run the command with the `vault_sh` tool: it exports every token into that command\'s environment,',
  'so the command text says `$GITHUB_TOKEN` and the value never appears in the session, a job record, or a receipt.',
  '`{{token:…}}` placeholders are NOT substituted any more; a `bash` or `run_code` call that contains one is refused.',
  'Saving, changing or deleting a token is the user\'s action in the panel; this tool cannot read values.',
].join(' ')

const TOOL_USAGE = [
  'Use a token by running the command with `vault_sh` and referencing the token as an exported environment variable',
  '(for example: vault_sh({ description: "check GitHub identity", command: \'curl -sS -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user\' })).',
  'Other tools (including `write` and `edit`, prompts, and hand-offs) treat a placeholder as inert text, so documentation may spell {{token:NAME}} literally.',
  'Add, change or delete tokens in Settings → 令牌库 (Token vault).',
].join(' ')

export function apply(ctx, config = {}) {
  const file = typeof config.file === 'string' && config.file !== '' ? config.file : defaultFile()
  const vault = new TokenVault(file, ctx.logger)
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

  /** The value-free catalogue, each entry carrying the environment name it exports. */
  const listWithEnv = () => {
    const envByToken = new Map(vault.environment().exports.map((entry) => [entry.name, entry.env]))
    return vault.list().map((token) => ({ ...token, env: envByToken.get(token.name) ?? token.name }))
  }

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
      sendJson(res, 500, { message: 'the token vault could not complete this operation' })
    }
  }

  // GET the value-free catalogue.
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
            return { tokens: listWithEnv() }
          })
        },
      }),
    `token-vault: GET ${LIST_PATH}`,
  )

  // POST create or update one token (a value may be omitted to keep the current one).
  ctx.effect(
    () =>
      ctx.webServer.register({
        kind: 'exact',
        path: SAVE_PATH,
        handler: async (req, res) => {
          if (rejected(req, res)) return
          if (req.method !== 'POST') {
            sendMethodNotAllowed(res, 'POST')
            return
          }
          const body = await readObjectBody(req)
          if (body === null) {
            sendJson(res, 400, { message: 'the request body must be a JSON object' })
            return
          }
          const tokenName = typeof body.name === 'string' ? body.name : ''
          if (!NAME_PATTERN.test(tokenName)) {
            sendJson(res, 400, {
              message: 'the name must start with a letter or underscore and use only letters, digits, dot, dash or underscore',
            })
            return
          }
          if (body.value !== undefined && typeof body.value !== 'string') {
            sendJson(res, 400, { message: 'the value must be a string' })
            return
          }
          if (body.note !== undefined && typeof body.note !== 'string') {
            sendJson(res, 400, { message: 'the note must be a string' })
            return
          }
          await respond(res, async () => {
            const token = await vault.save({
              name: tokenName,
              ...body.value === undefined ? {} : { value: body.value },
              ...body.note === undefined ? {} : { note: body.note },
            })
            return { token }
          })
        },
      }),
    `token-vault: POST ${SAVE_PATH}`,
  )

  // POST delete one token.
  ctx.effect(
    () =>
      ctx.webServer.register({
        kind: 'exact',
        path: DELETE_PATH,
        handler: async (req, res) => {
          if (rejected(req, res)) return
          if (req.method !== 'POST') {
            sendMethodNotAllowed(res, 'POST')
            return
          }
          const body = await readObjectBody(req)
          const tokenName = typeof body?.name === 'string' ? body.name : ''
          if (!NAME_PATTERN.test(tokenName)) {
            sendJson(res, 400, { message: 'a valid token name is required' })
            return
          }
          await respond(res, async () => {
            await vault.remove(tokenName)
            return { tokens: listWithEnv() }
          })
        },
      }),
    `token-vault: POST ${DELETE_PATH}`,
  )

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
              : 'The token vault is empty; the user adds tokens in Settings → 令牌库 (Token vault).',
            'A substituted command line would be recorded verbatim in the job log and could leak the value.',
          ].join(' '),
        }
      }),
    'token-vault: placeholder guard',
  )

  // Scrub stored values out of tool output so an echoing command cannot leak one.
  ctx.effect(
    () =>
      ctx.on('tools/post-execute', async (exec, result, next) => {
        const decision = await next()
        if (decision.kind !== 'accept') return decision
        const content = vault.scrubContent(decision.content ?? result.content)
        if (content === (decision.content ?? result.content)) return decision
        return {
          kind: 'accept',
          content,
          ...decision.additionalContexts === undefined ? {} : { additionalContexts: decision.additionalContexts },
        }
      }),
    'token-vault: result scrub',
  )

  // Scrub stored values out of tool output so an echoing command cannot leak one.
  ctx.effect(
    () =>
      ctx.on('tools/post-execute', async (exec, result, next) => {
        const decision = await next()
        if (decision.kind !== 'accept') return decision
        const content = vault.scrubContent(decision.content ?? result.content)
        if (content === (decision.content ?? result.content)) return decision
        return {
          kind: 'accept',
          content,
          ...decision.additionalContexts === undefined ? {} : { additionalContexts: decision.additionalContexts },
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
              enum: ['list'],
              description: 'Only `list` is available: returns token names, notes and lengths. Values are never returned.',
            },
          },
        },
        output: {
          schema: {
            type: 'object',
            additionalProperties: false,
            required: ['tokens', 'usage'],
            properties: {
              tokens: {
                type: 'array',
                items: {
                  type: 'object',
                  additionalProperties: false,
                  required: ['name', 'note', 'length', 'env'],
                  properties: {
                    name: { type: 'string' },
                    note: { type: 'string' },
                    length: { type: 'number' },
                    env: { type: 'string' },
                  },
                },
              },
              usage: { type: 'string' },
            },
          },
          render(_args, value) {
            const lines = []
            if (value.tokens.length === 0) {
              lines.push('The local token vault is empty.')
            } else {
              lines.push(`Stored tokens (values hidden, ${value.tokens.length}):`)
              for (const token of value.tokens) {
                const note = token.note === '' ? '' : ` — ${token.note}`
                lines.push(`- ${token.name}${note} (${token.length} characters) → $${token.env}`)
              }
            }
            lines.push('', value.usage)
            return [{ type: 'text', text: lines.join('\n') }]
          },
        },
        async execute() {
          await vault.ready()
          return {
            tokens: listWithEnv().map((token) => ({
              name: token.name,
              note: token.note,
              length: token.length,
              env: token.env,
            })),
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
          'The value never appears in the command text, the session log, or a job record; tool output is scrubbed if a command echoes one.',
          'The command runs under the same sandbox policy, working directory and DSH_* environment as `bash`.',
          'Use this instead of `bash` whenever a command needs a stored token; `{{token:…}}` placeholders are refused.',
        ].join(' '),
        parameters: {
          type: 'object',
          additionalProperties: false,
          required: ['description', 'command'],
          properties: {
            description: {
              type: 'string',
              description: 'Clear, concise description of what this command does in active voice, 5-10 words (shown in the UI).',
            },
            command: {
              type: 'string',
              description: 'The bash command, referring to tokens as environment variables such as $GITHUB_TOKEN.',
            },
            workdir: {
              type: 'string',
              description: 'Working directory. Defaults to the session workspace; a relative path is resolved against it.',
            },
            timeoutMs: {
              type: 'number',
              description: 'Timeout in milliseconds; the executor applies its configured default and cap and kills the command on expiry.',
            },
          },
        },
        output: {
          schema: {
            type: 'object',
            additionalProperties: false,
            required: ['cwd', 'exitCode', 'signal', 'timedOut', 'aborted', 'stdout', 'stderr', 'exports'],
            properties: {
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
          render(_args, value) {
            const exported = value.exports.length === 0
              ? 'tokens exported: none (the vault is empty)'
              : `tokens exported: ${value.exports.map((entry) => `${entry.name} → $${entry.env}`).join(', ')}`
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
          const { env, exports } = vault.environment()
          const cwd = exec.agent === undefined ? undefined : await ctx.workingDirectory.ensure(exec.agent, exec.signal)
          const workdir = resolveWorkdir(args.workdir, cwd)
          const policy = resolveSandboxPolicy(exec)
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
          const tokens = vault.list()
          if (tokens.length === 0) return ''
          const rows = tokens.map((token) => (token.note === '' ? `- ${token.name}` : `- ${token.name} — ${token.note}`))
          return [
            '## Token vault',
            '',
            'The user keeps these secrets in the local token vault; their values are never shown in this session:',
            ...rows,
            '',
            `Run a command that needs one with \`${SHELL_TOOL_NAME}\`, which exports each token into the child environment:`,
            `  ${SHELL_TOOL_NAME}({ description: "check GitHub identity", command: 'curl -sS -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user' })`,
            'Reference tokens as `$NAME` (double quotes or unquoted). Single quotes do not expand variables.',
            'Values never enter the command text, so they cannot reach the session log, a job record, or a receipt; tool output is scrubbed if a command echoes one.',
            'Never write `{{token:…}}` inside a `bash` or `run_code` call: placeholders are no longer substituted, and such a call is refused.',
            'Everywhere else (documents, prompts, hand-offs) the placeholder stays inert text, so documentation can spell the syntax.',
            'Adding, changing or deleting a token is the user\'s action in Settings → 令牌库 (Token vault); call the `token_vault` tool to re-list them.',
          ].join('\n')
        },
      }),
    'token-vault: prompt section',
  )
}
