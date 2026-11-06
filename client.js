/**
 * Token vault — the browser half.
 *
 * Renders the "Token vault" page inside Settings. The page is the only place
 * tokens are written: it lists names, notes and value lengths (never values),
 * and every operation goes to the Host routes the package's other half serves.
 *
 * @module @local/token-vault/client
 */

window.__ModuleLoader__.load({
  id: '@local/token-vault',
  factory(require) {
    const React = require('react')
    const { useCallback, useEffect, useState, useSyncExternalStore } = React
    const h = React.createElement

    const LOCALE_NS = 'token-vault'
    const LIST_ROUTE = 'token-vault/list'
    const SAVE_ROUTE = 'token-vault/save'
    const DELETE_ROUTE = 'token-vault/delete'
    const NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/
    const SHELL_EXAMPLE = 'vault_sh: curl -sS -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user'

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
        'action.save': 'Save token',
        'action.saving': 'Saving…',
        'action.saveChanges': 'Save',
        'action.cancel': 'Cancel',
        'action.copyVariable': 'Copy $NAME',
        'action.copied': 'Copied',
        'action.replace': 'Replace value',
        'action.delete': 'Delete',
        'action.confirmDelete': 'Confirm delete',
        'list.title': 'Stored tokens',
        'list.count': '{count} total',
        'list.loading': 'Loading…',
        'list.empty': 'No tokens yet — add one above.',
        'row.hidden': '•••••••• · {count} characters',
        'usage.line':
          'Any session runs a command needing a token with the vault_sh tool; the token is exported into that command\'s environment, so only $NAME appears in the session.',
        'usage.example': SHELL_EXAMPLE,
        'error.nameRequired': 'Enter a name.',
        'error.nameInvalid': 'Start with a letter or underscore; then letters, digits, dot, dash or underscore.',
        'error.valueRequired': 'Enter the token value.',
        'error.copyFailed': 'The clipboard is not available in this browser.',
        'notice.saved': 'Saved {name}.',
        'notice.updated': 'Updated {name}.',
        'notice.deleted': 'Deleted {name}.',
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
        'action.save': '保存令牌',
        'action.saving': '保存中…',
        'action.saveChanges': '保存',
        'action.cancel': '取消',
        'action.copyVariable': '复制 $NAME',
        'action.copied': '已复制',
        'action.replace': '替换值',
        'action.delete': '删除',
        'action.confirmDelete': '确认删除',
        'list.title': '已保存的令牌',
        'list.count': '共 {count} 个',
        'list.loading': '加载中…',
        'list.empty': '还没有令牌，在上面的表单里添加一个。',
        'row.hidden': '•••••••• · {count} 个字符',
        'usage.line': '任意会话用 vault_sh 跑命令即可用到令牌：令牌被注入该命令的环境变量，会话里只会出现 $NAME。',
        'usage.example': SHELL_EXAMPLE,
        'error.nameRequired': '请填写名称。',
        'error.nameInvalid': '请以字母或下划线开头，只能包含字母、数字、点、横线或下划线。',
        'error.valueRequired': '请填写令牌值。',
        'error.copyFailed': '当前浏览器不允许访问剪贴板。',
        'notice.saved': '已保存 {name}。',
        'notice.updated': '已更新 {name}。',
        'notice.deleted': '已删除 {name}。',
      },
    }

    const STYLE = `
.tv-section{display:flex;flex-direction:column;gap:16px;width:100%;max-width:760px;color:var(--dsw-alias-label-primary);font-size:14px;line-height:22px}
.tv-lead{margin:0;color:var(--dsw-alias-label-tertiary);font-size:12px;line-height:18px}
.tv-form{display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end;padding:14px;border:.5px solid var(--dsw-alias-border-l1);border-radius:12px;background:var(--dsw-alias-bg-layer-1)}
.tv-field{display:flex;flex-direction:column;gap:6px;flex:1 1 170px;min-width:0}
.tv-field>span{color:var(--dsw-alias-label-secondary);font-size:12px;font-weight:500;line-height:18px}
.tv-input{box-sizing:border-box;width:100%;height:32px;padding:0 10px;border:.5px solid var(--dsw-alias-border-l4);border-radius:8px;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);font:inherit;font-size:14px;line-height:22px}
.tv-input::placeholder{color:var(--dsw-alias-label-tertiary)}
.tv-input:focus-visible{outline:2px solid var(--dsw-alias-brand-primary);outline-offset:-1px}
.tv-primary{box-sizing:border-box;height:32px;padding:0 14px;border:none;border-radius:8px;background:var(--dsw-alias-button-primary-fill);color:var(--dsw-alias-label-primary-foreground);font:inherit;font-size:13px;line-height:20px;cursor:pointer;white-space:nowrap}
.tv-primary:disabled{opacity:.55;cursor:default}
.tv-listHead{display:flex;align-items:baseline;gap:8px}
.tv-listTitle{margin:0;font-size:14px;font-weight:500;line-height:22px}
.tv-count{color:var(--dsw-alias-label-tertiary);font-size:12px;line-height:18px;font-variant-numeric:tabular-nums}
.tv-empty{margin:0;color:var(--dsw-alias-label-tertiary);font-size:12px;line-height:18px}
.tv-list{display:flex;flex-direction:column;gap:8px;margin:0;padding:0;list-style:none}
.tv-row{display:flex;flex-direction:column;gap:6px;padding:12px 14px;border:.5px solid var(--dsw-alias-settings-card-stroke,var(--dsw-alias-border-l1));border-radius:12px;background:var(--dsw-alias-settings-card-fill,var(--dsw-alias-bg-layer-1))}
.tv-rowMain{display:flex;flex-wrap:wrap;align-items:center;gap:6px 10px;min-width:0}
.tv-name{flex:none;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;line-height:20px;color:var(--dsw-alias-label-primary);background:var(--dsw-alias-bg-module-platform,transparent);border-radius:6px;padding:1px 6px}
.tv-env{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary);background:var(--dsw-alias-bg-layer-2);border-radius:6px;padding:1px 6px;white-space:nowrap}
.tv-masked{color:var(--dsw-alias-label-tertiary);font-size:12px;line-height:18px;white-space:nowrap}
.tv-when{margin-left:auto;color:var(--dsw-alias-label-tertiary);font-size:12px;line-height:18px;font-variant-numeric:tabular-nums;white-space:nowrap}
.tv-note{margin:0;color:var(--dsw-alias-label-secondary);font-size:12px;line-height:18px;overflow-wrap:anywhere}
.tv-actions{display:flex;flex-wrap:wrap;align-items:center;gap:2px}
.tv-link{box-sizing:border-box;height:28px;padding:0 10px;border:none;border-radius:6px;background:0 0;color:var(--dsw-alias-label-tertiary);font:inherit;font-size:12px;line-height:18px;cursor:pointer}
.tv-link:hover{background:var(--dsw-alias-interactive-bg-hover,var(--dsw-alias-bg-layer-2));color:var(--dsw-alias-label-primary)}
.tv-danger{box-sizing:border-box;height:28px;padding:0 10px;border:none;border-radius:6px;background:0 0;color:var(--dsw-alias-state-error-primary);font:inherit;font-size:12px;line-height:18px;cursor:pointer}
.tv-danger:hover{background:var(--dsw-alias-interactive-bg-hover,var(--dsw-alias-bg-layer-2))}
.tv-edit{display:flex;flex-wrap:wrap;align-items:flex-end;gap:10px}
.tv-error{margin:0;color:var(--dsw-alias-state-error-primary);font-size:12px;line-height:18px}
.tv-notice{margin:0;color:var(--dsw-alias-state-success-primary);font-size:12px;line-height:18px}
.tv-usage{display:flex;flex-direction:column;gap:6px;padding-top:12px;border-top:.5px solid var(--dsw-alias-border-l1)}
.tv-usage p{margin:0;color:var(--dsw-alias-label-tertiary);font-size:12px;line-height:18px}
.tv-usage code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary);background:var(--dsw-alias-bg-layer-1);border:.5px solid var(--dsw-alias-border-l1);border-radius:6px;padding:6px 8px;overflow-wrap:anywhere}
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

    /** Human-readable message for one failed route call. */
    function messageOf(failure) {
      if (failure instanceof Error && failure.message !== '') return failure.message
      return String(failure)
    }

    /** One JSON route call; a non-2xx answer keeps the Host's own message. */
    async function call(route, body) {
      const init =
        body === undefined
          ? { method: 'GET' }
          : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }
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

    /** One stored token: name, masked length, note, and its value-free actions. */
    function TokenRow(props) {
      const token = props.token
      const editing = props.editing !== null && props.editing.name === token.name
      const pendingDelete = props.pendingDelete === token.name
      const when = props.formatWhen(token.updatedAt)
      return h(
        'li',
        { className: 'tv-row' },
        h(
          'div',
          { className: 'tv-rowMain' },
          h('code', { className: 'tv-name' }, token.name),
          token.env === undefined ? null : h('code', { className: 'tv-env' }, `$${token.env}`),
          h('span', { className: 'tv-masked' }, t('row.hidden', { count: token.length })),
          when === '' ? null : h('span', { className: 'tv-when' }, when),
        ),
        token.note === '' ? null : h('p', { className: 'tv-note' }, token.note),
        editing
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
                'button',
                { type: 'button', className: 'tv-link', onClick: () => props.onCopy(token) },
                props.copied === token.name ? t('action.copied') : t('action.copyVariable'),
              ),
              h('button', { type: 'button', className: 'tv-link', onClick: () => props.onEdit(token) }, t('action.replace')),
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
      const [tokens, setTokens] = useState(null)
      const [error, setError] = useState('')
      const [notice, setNotice] = useState('')
      const [busy, setBusy] = useState(false)
      const [draft, setDraft] = useState({ name: '', value: '', note: '' })
      const [editing, setEditing] = useState(null)
      const [pendingDelete, setPendingDelete] = useState('')
      const [copied, setCopied] = useState('')

      const refresh = useCallback(async () => {
        try {
          const payload = await call(LIST_ROUTE)
          setTokens(Array.isArray(payload.tokens) ? payload.tokens : [])
        } catch (failure) {
          setError(messageOf(failure))
          setTokens((current) => current ?? [])
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

      const submitDraft = async (event) => {
        event.preventDefault()
        if (busy) return
        const name = draft.name.trim()
        if (name === '') return setError(t('error.nameRequired'))
        if (!NAME_PATTERN.test(name)) return setError(t('error.nameInvalid'))
        if (draft.value === '') return setError(t('error.valueRequired'))
        setBusy(true)
        setError('')
        setNotice('')
        try {
          await call(SAVE_ROUTE, { name, value: draft.value, note: draft.note })
          setDraft({ name: '', value: '', note: '' })
          setNotice(t('notice.saved', { name }))
          await refresh()
        } catch (failure) {
          setError(messageOf(failure))
        } finally {
          setBusy(false)
        }
      }

      const submitEdit = async (event) => {
        event.preventDefault()
        if (busy || editing === null) return
        const body = { name: editing.name, note: editing.note }
        if (editing.value !== '') body.value = editing.value
        setBusy(true)
        setError('')
        setNotice('')
        try {
          await call(SAVE_ROUTE, body)
          const name = editing.name
          setEditing(null)
          setNotice(t('notice.updated', { name }))
          await refresh()
        } catch (failure) {
          setError(messageOf(failure))
        } finally {
          setBusy(false)
        }
      }

      const remove = async (name) => {
        if (pendingDelete !== name) {
          setPendingDelete(name)
          return
        }
        setBusy(true)
        setError('')
        setNotice('')
        try {
          const payload = await call(DELETE_ROUTE, { name })
          setTokens(Array.isArray(payload.tokens) ? payload.tokens : [])
          setPendingDelete('')
          setNotice(t('notice.deleted', { name }))
        } catch (failure) {
          setError(messageOf(failure))
        } finally {
          setBusy(false)
        }
      }

      const copyVariable = async (token) => {
        try {
          await navigator.clipboard.writeText(`$${token.env ?? token.name}`)
          setCopied(token.name)
        } catch {
          setError(t('error.copyFailed'))
        }
      }

      const formatWhen = (value) => {
        if (typeof value !== 'string' || value === '') return ''
        const date = new Date(value)
        if (Number.isNaN(date.getTime())) return ''
        return date.toLocaleString()
      }

      return h(
        'div',
        { className: 'tv-section' },
        h('style', { key: 'style' }, STYLE),
        h('p', { className: 'tv-lead' }, t('lead')),
        h(
          'form',
          { className: 'tv-form', onSubmit: submitDraft, autoComplete: 'off' },
          h(Field, {
            label: t('field.name'),
            value: draft.name,
            placeholder: t('field.namePlaceholder'),
            onChange: (event) => setDraft({ ...draft, name: event.target.value }),
          }),
          h(Field, {
            label: t('field.value'),
            type: 'password',
            autoComplete: 'new-password',
            value: draft.value,
            placeholder: t('field.valuePlaceholder'),
            onChange: (event) => setDraft({ ...draft, value: event.target.value }),
          }),
          h(Field, {
            label: t('field.note'),
            value: draft.note,
            placeholder: t('field.notePlaceholder'),
            onChange: (event) => setDraft({ ...draft, note: event.target.value }),
          }),
          h('button', { type: 'submit', className: 'tv-primary', disabled: busy }, busy ? t('action.saving') : t('action.save')),
        ),
        error === '' ? null : h('p', { className: 'tv-error', role: 'alert' }, error),
        notice === '' ? null : h('p', { className: 'tv-notice' }, notice),
        h(
          'div',
          { className: 'tv-listHead' },
          h('h3', { className: 'tv-listTitle' }, t('list.title')),
          tokens === null ? null : h('span', { className: 'tv-count' }, t('list.count', { count: tokens.length })),
        ),
        tokens === null
          ? h('p', { className: 'tv-empty' }, t('list.loading'))
          : tokens.length === 0
            ? h('p', { className: 'tv-empty' }, t('list.empty'))
            : h(
                'ul',
                { className: 'tv-list' },
                tokens.map((token) =>
                  h(TokenRow, {
                    key: token.name,
                    token,
                    editing,
                    pendingDelete,
                    copied,
                    busy,
                    formatWhen,
                    onCopy: copyVariable,
                    onEdit: (target) => {
                      setPendingDelete('')
                      setEditing({ name: target.name, value: '', note: target.note })
                    },
                    onEditValue: (value) => setEditing((current) => (current === null ? current : { ...current, value })),
                    onEditNote: (value) => setEditing((current) => (current === null ? current : { ...current, note: value })),
                    onCancelEdit: () => setEditing(null),
                    onSubmitEdit: submitEdit,
                    onDelete: remove,
                  }),
                ),
              ),
        h(
          'div',
          { className: 'tv-usage' },
          h('p', null, t('usage.line')),
          h('code', null, t('usage.example')),
        ),
      )
    }

    const PAGE_ID = 'token-vault'

    const PAGE_STYLE =
      '.tv-page{display:flex;flex-direction:column;width:100%;height:100%;min-height:0;overflow:auto;scrollbar-gutter:stable;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary)}' +
      '.tv-page-inner{box-sizing:border-box;width:100%;max-width:820px;margin:0 auto;padding:26px clamp(20px,4vw,40px) 48px}'

    /** Full-page shell so the vault also works as a `main` panel (hub tab). */
    function TokenPage() {
      return h(
        'div',
        { className: 'tv-page' },
        h('style', { key: 'page-style' }, PAGE_STYLE),
        h('div', { className: 'tv-page-inner' }, h(TokenSection)),
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
