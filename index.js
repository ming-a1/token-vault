/**
 * Token vault — the Host half.
 *
 * A small local store for Git and other API tokens, plus the two mechanisms
 * that let any Session use one without the value ever entering the Session:
 *
 * 1. `{{token:NAME}}` placeholders inside a tool call's arguments are replaced
 *    with the stored value immediately before the tool is dispatched
 *    (`tools/execute`), so the durable log keeps the placeholder only.
 * 2. Every text block of a tool result is scrubbed back to its placeholder
 *    (`tools/post-execute`), so a command that echoes a token cannot leak it.
 *
 * The value itself is never returned by any route or tool: the panel reads
 * names, notes and value lengths; the agent tool reads names and notes.
 *
 * @module @local/token-vault
 */

import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

/** Cordis plugin name. */
export const name = 'token-vault'

/** The route carrier, its trust fence, the tool registry and the prompt. */
export const inject = ['webServer', 'connection', 'tools', 'systemPrompt']

/** Accepted token names: a shell-friendly identifier. */
const NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/

/** One `{{token:NAME}}` placeholder occurrence. */
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
 * Tools whose arguments are document text rather than something that executes.
 * They keep `{{token:…}}` literally: documentation, templates and changelogs
 * must be able to spell the syntax, and writing a real secret into a file is a
 * decision the user makes in the panel, not a side effect of a placeholder.
 */
const CONTENT_TOOLS = new Set(['write', 'edit'])

/** Route paths served to the panel (the browser addresses them document-relative). */
const LIST_PATH = '/token-vault/list'
const SAVE_PATH = '/token-vault/save'
const DELETE_PATH = '/token-vault/delete'

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
   * Collect the placeholder names one argument tree references that the vault
   * does not hold, so the call can be refused before it runs with a literal
   * placeholder in it.
   *
   * @param value - candidate tool arguments.
   * @returns unknown names, in first-seen order.
   */
  missing(value) {
    const unknown = new Set()
    const visit = (node) => {
      if (typeof node === 'string') {
        if (!node.includes('{{')) return
        for (const match of node.matchAll(PLACEHOLDER_PATTERN)) {
          if (!this.tokens.has(match[1])) unknown.add(match[1])
        }
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
    return [...unknown]
  }

  /**
   * Replace every known placeholder in an argument tree with its stored value.
   *
   * @param value - tool arguments.
   * @returns the substituted copy and whether anything changed.
   */
  substitute(value) {
    let changed = false
    const visit = (node) => {
      if (typeof node === 'string') {
        if (!node.includes('{{')) return node
        const next = node.replace(PLACEHOLDER_PATTERN, (match, tokenName) => {
          const entry = this.tokens.get(tokenName)
          if (entry === undefined) return match
          changed = true
          return entry.value
        })
        return next
      }
      if (Array.isArray(node)) return node.map(visit)
      if (node !== null && typeof node === 'object') {
        const out = {}
        for (const [key, item] of Object.entries(node)) out[key] = visit(item)
        return out
      }
      return node
    }
    const substituted = visit(value)
    return { value: substituted, changed }
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

/** The agent-facing tool: names and notes only, never a value. */
const TOOL_NAME = 'token_vault'

const TOOL_DESCRIPTION = [
  'List the tokens held by the local token vault (opened from Settings → 令牌库 / Token vault).',
  'Values are never returned: the vault only reports each token name, its note and its length.',
  'To use a token in another tool call, write the placeholder {{token:NAME}} where the value belongs —',
  'for example `git clone https://oauth2:{{token:GITHUB_TOKEN}}@github.com/org/repo.git` inside a bash command.',
  'The vault replaces the placeholder with the real value immediately before the tool runs, and scrubs any',
  'stored value back to its placeholder from tool output, so the token never appears in the session.',
  'Saving, changing or deleting a token is the user\'s action in the panel; this tool cannot read values.',
].join(' ')

const TOOL_USAGE = [
  'Reference a token from another tool call by writing {{token:NAME}} where its value belongs; it is replaced',
  'right before the tool runs, so the value never enters this session. `write` and `edit` arguments are exempt',
  '(documentation may spell the syntax). Add, change or delete tokens in Settings → 令牌库 (Token vault).',
].join(' ')

export function apply(ctx, config = {}) {
  const file = typeof config.file === 'string' && config.file !== '' ? config.file : defaultFile()
  const vault = new TokenVault(file, ctx.logger)
  // Prompt assembly is synchronous; warm the cache in the background and let a
  // failed read surface on the first route or tool call instead.
  vault.ready().catch((error) => ctx.logger?.warn?.(`token-vault: cannot read ${file}: ${String(error)}`))

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
            return { tokens: vault.list() }
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
            return { tokens: vault.list() }
          })
        },
      }),
    `token-vault: POST ${DELETE_PATH}`,
  )

  // Refuse a call that references a token the vault does not hold: it would run
  // with the literal placeholder instead of a value. Document-text tools are
  // exempt — they are allowed to spell the placeholder syntax.
  ctx.effect(
    () =>
      ctx.on('tools/pre-execute', async (exec, next) => {
        if (CONTENT_TOOLS.has(exec.name)) return next()
        const unknown = vault.missing(exec.arguments)
        if (unknown.length === 0) return next()
        const known = vault.list().map((token) => token.name)
        return {
          kind: 'deny',
          reason: [
            `unknown token placeholder${unknown.length > 1 ? 's' : ''}: ${unknown.map((entry) => `{{token:${entry}}}`).join(', ')}.`,
            known.length > 0 ? `Stored tokens: ${known.join(', ')}.` : 'The token vault is empty.',
            'The user adds and changes tokens in Settings → 令牌库 (Token vault).',
          ].join(' '),
        }
      }),
    'token-vault: placeholder guard',
  )

  // Substitute placeholders right before dispatch. The tool call as logged and
  // presented keeps the placeholder; only the executing arguments carry values.
  ctx.effect(
    () =>
      ctx.on('tools/execute', async (exec, next) => {
        if (!CONTENT_TOOLS.has(exec.name) && exec.arguments !== undefined) {
          const substituted = vault.substitute(exec.arguments)
          if (substituted.changed) {
            try {
              exec.arguments = substituted.value
            } catch (error) {
              ctx.logger?.warn?.(`token-vault: cannot substitute placeholders for ${exec.name}: ${String(error)}`)
            }
          }
        }
        return next()
      }),
    'token-vault: placeholder substitution',
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
                  required: ['name', 'note', 'length', 'placeholder'],
                  properties: {
                    name: { type: 'string' },
                    note: { type: 'string' },
                    length: { type: 'number' },
                    placeholder: { type: 'string' },
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
                lines.push(`- ${token.name}${note} (${token.length} characters) → ${token.placeholder}`)
              }
            }
            lines.push('', value.usage)
            return [{ type: 'text', text: lines.join('\n') }]
          },
        },
        async execute() {
          await vault.ready()
          return {
            tokens: vault.list().map((token) => ({
              name: token.name,
              note: token.note,
              length: token.length,
              placeholder: `{{token:${token.name}}}`,
            })),
            usage: TOOL_USAGE,
          }
        },
      }),
    'token-vault: tool',
  )

  // Advertise the token names (never values) so every Session can reference them
  // without a discovery round trip. `interpolate: false` keeps the documented
  // placeholder literal instead of letting prompt variables consume it.
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
            'Use one by writing {{token:NAME}} where its value belongs in a tool call\'s arguments (for example inside a bash command).',
            'The vault replaces the placeholder with the real value right before the tool runs, and scrubs stored values out of tool output.',
            '`write` and `edit` arguments are exempt, so documentation and templates can spell the placeholder literally.',
            'Adding, changing or deleting a token is the user\'s action in Settings → 令牌库 (Token vault); call the `token_vault` tool to re-list them.',
          ].join('\n')
        },
      }),
    'token-vault: prompt section',
  )
}
