<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import type { Connection, ConnectionUpdate, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import { lines } from '../applications/defaults'
import { asRecord, mergeOptions, optionsOf, parseJSON, pretty, unknownOptions, type Options } from './options'
import StoredMark from './StoredMark.vue'

const { t } = useI18n()

const props = defineProps<{ tenant: SystemTenant; connection: Connection }>()
const emit = defineEmits<{ saved: [Connection] }>()
const { api } = useServices()

// Settings zeroauthy stores and returns without acting on (D-0042). Each is
// marked "saved, not enforced yet".
type Kind = 'json' | 'lines' | 'bool' | 'text'
interface Spec {
  key: string
  where: 'options' | 'top'
  kind: Kind
}
const stored: Spec[] = [
  { key: 'display_name', where: 'top', kind: 'text' },
  { key: 'show_as_button', where: 'top', kind: 'bool' },
  { key: 'realms', where: 'top', kind: 'lines' },
  { key: 'metadata', where: 'top', kind: 'json' },
  { key: 'connected_accounts', where: 'top', kind: 'json' },
  { key: 'authentication', where: 'top', kind: 'json' },
  { key: 'authentication_methods', where: 'options', kind: 'json' },
  { key: 'passkey_options', where: 'options', kind: 'json' },
  { key: 'attributes', where: 'options', kind: 'json' },
  { key: 'precedence', where: 'options', kind: 'lines' },
  { key: 'mfa', where: 'options', kind: 'json' },
  { key: 'disable_self_service_change_password', where: 'options', kind: 'bool' },
  { key: 'non_persistent_attrs', where: 'options', kind: 'lines' },
]

const form = reactive({ brute: true, disableSignup: false, requiresUsername: false, domain: false, usernameMin: '', usernameMax: '' })
const values = reactive<Record<string, string | boolean>>({})
const errors = reactive<Record<string, string>>({})
const general = ref('')
const status = ref('')
const busy = ref(false)
let initial: Record<string, string | boolean> = {}

function source(s: Spec): unknown {
  return s.where === 'top' ? (props.connection as Record<string, unknown>)[s.key] : optionsOf(props.connection)[s.key]
}

function format(s: Spec): string | boolean {
  const v = source(s)
  switch (s.kind) {
    case 'bool':
      return v === true
    case 'text':
      return typeof v === 'string' ? v : ''
    case 'lines':
      return Array.isArray(v) ? v.filter((x) => typeof x === 'string').join('\n') : ''
    default:
      return v === undefined || v === null ? '' : pretty(v)
  }
}

function reset(c: Connection) {
  const o = optionsOf(c)
  form.brute = o.brute_force_protection !== false
  form.disableSignup = o.disable_signup === true
  form.requiresUsername = o.requires_username === true
  form.domain = c.is_domain_connection
  const u = asRecord(asRecord(o.validation).username)
  form.usernameMin = typeof u.min === 'number' ? String(u.min) : ''
  form.usernameMax = typeof u.max === 'number' ? String(u.max) : ''
  initial = {}
  for (const s of stored) {
    initial[s.key] = format(s)
    values[s.key] = format(s)
  }
}
watch(() => props.connection, reset, { immediate: true })

const unknown = computed(() => unknownOptions(optionsOf(props.connection)))

function wholeNumber(text: string): number | null {
  return /^\d+$/.test(text.trim()) ? Number(text) : null
}

async function save() {
  general.value = ''
  status.value = ''
  for (const k of Object.keys(errors)) delete errors[k]

  // A switch left where it was is not written, so an option the connection
  // never named stays unnamed.
  const cur = optionsOf(props.connection)
  const edits: Options = {}
  if (form.brute !== (cur.brute_force_protection !== false)) edits.brute_force_protection = form.brute
  if (form.disableSignup !== (cur.disable_signup === true)) edits.disable_signup = form.disableSignup
  if (form.requiresUsername !== (cur.requires_username === true)) edits.requires_username = form.requiresUsername
  const top: ConnectionUpdate = {}
  const topWrite = top as Record<string, unknown>

  // validation.username keeps the other keys of validation.
  const minText = form.usernameMin.trim()
  const maxText = form.usernameMax.trim()
  const validation = { ...asRecord(optionsOf(props.connection).validation) }
  if (minText || maxText) {
    const min = wholeNumber(minText)
    const max = wholeNumber(maxText)
    if (min === null || min < 1) errors.usernameMin = t('conns.usernameMinInvalid')
    if (max === null || max > 128) errors.usernameMax = t('conns.usernameMaxInvalid')
    if (min !== null && max !== null && !errors.usernameMin && !errors.usernameMax && min >= max) errors.usernameMax = t('conns.usernameOrder')
    validation.username = { ...asRecord(validation.username), min, max }
  } else {
    delete validation.username
  }
  edits.validation = Object.keys(validation).length ? validation : undefined

  for (const s of stored) {
    const v = values[s.key]
    if (v === initial[s.key]) continue
    let next: unknown
    if (s.kind === 'bool' || s.kind === 'text') next = v
    else if (s.kind === 'lines') next = lines(String(v))
    else if (String(v).trim() === '') next = s.where === 'top' ? {} : undefined
    else {
      next = parseJSON(String(v), 'object')
      if (next === null) {
        errors[s.key] = t('conns.jsonObject')
        continue
      }
    }
    if (s.key === 'realms' && (next as string[]).length === 0) {
      errors[s.key] = t('conns.realmsRequired')
      continue
    }
    if (s.where === 'top') topWrite[s.key] = next
    else edits[s.key] = s.kind === 'lines' && (next as string[]).length === 0 ? undefined : next
  }
  if (form.domain !== props.connection.is_domain_connection) top.is_domain_connection = form.domain
  if (Object.keys(errors).length) return

  busy.value = true
  try {
    // options is replaced whole: send the last GET's options with these
    // edits laid over them.
    const c = await api.updateConnection(props.tenant, props.connection.id, { ...top, options: mergeOptions(optionsOf(props.connection), edits) })
    status.value = t('saved')
    emit('saved', c)
  } catch (e) {
    general.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <form class="stack" novalidate @submit.prevent="save">
    <Banner v-if="general" kind="error">{{ general }}</Banner>

    <section class="card stack" :aria-label="t('conns.enforcedGroup')">
      <h2>{{ t('conns.enforcedGroup') }}</h2>
      <label class="check">
        <input v-model="form.brute" type="checkbox" />
        <span><strong>{{ t('conns.bruteForce') }}</strong><span class="muted">{{ t('conns.bruteForceHint') }}</span></span>
      </label>
      <label class="check">
        <input v-model="form.disableSignup" type="checkbox" />
        <span><strong>{{ t('conns.disableSignup') }}</strong><span class="muted">{{ t('conns.disableSignupHint') }}</span></span>
      </label>
      <label class="check">
        <input v-model="form.requiresUsername" type="checkbox" />
        <span><strong>{{ t('conns.requiresUsername') }}</strong><span class="muted">{{ t('conns.requiresUsernameHint') }}</span></span>
      </label>
      <label class="check">
        <input v-model="form.domain" type="checkbox" />
        <span><strong>{{ t('conns.domainConnection') }}</strong><span class="muted">{{ t('conns.domainConnectionHint') }}</span></span>
      </label>
      <Field id="conn-username-min" :label="t('conns.usernameMin')" :hint="t('conns.usernameHint')" :error="errors.usernameMin">
        <input id="conn-username-min" v-model="form.usernameMin" type="text" inputmode="numeric" :aria-invalid="!!errors.usernameMin" />
      </Field>
      <Field id="conn-username-max" :label="t('conns.usernameMax')" :error="errors.usernameMax">
        <input id="conn-username-max" v-model="form.usernameMax" type="text" inputmode="numeric" :aria-invalid="!!errors.usernameMax" />
      </Field>
    </section>

    <section class="card stack" :aria-label="t('conns.storedGroup')" data-testid="stored-group">
      <h2>{{ t('conns.storedGroup') }} <StoredMark /></h2>
      <p class="muted">{{ t('conns.storedHint') }}</p>
      <template v-for="s in stored" :key="s.key">
        <label v-if="s.kind === 'bool'" class="check">
          <input v-model="values[s.key]" type="checkbox" />
          <span>
            <strong>{{ t(`conns.stored.${s.key}.label`) }} <StoredMark /></strong>
            <span v-if="t(`conns.stored.${s.key}.hint`)" class="muted">{{ t(`conns.stored.${s.key}.hint`) }}</span>
          </span>
        </label>
        <div v-else class="field">
          <label :for="'stored-' + s.key">{{ t(`conns.stored.${s.key}.label`) }} <StoredMark /></label>
          <input v-if="s.kind === 'text'" :id="'stored-' + s.key" v-model="values[s.key] as string" type="text" />
          <textarea
            v-else
            :id="'stored-' + s.key"
            v-model="values[s.key] as string"
            :class="{ mono: s.kind === 'json' }"
            rows="4"
            spellcheck="false"
            :aria-invalid="!!errors[s.key]"
            :aria-describedby="s.key + '-hint'"
          />
          <p :id="s.key + '-hint'" class="muted hint">{{ t(`conns.stored.${s.key}.hint`) }}</p>
          <p v-if="errors[s.key]" class="error" role="alert">{{ errors[s.key] }}</p>
        </div>
      </template>
    </section>

    <section class="card stack" :aria-label="t('conns.unknownGroup')" data-testid="unknown-group">
      <h2>{{ t('conns.unknownGroup') }} <StoredMark /></h2>
      <p class="muted">{{ t('conns.unknownHint') }}</p>
      <p v-if="Object.keys(unknown).length === 0" class="muted">{{ t('conns.unknownNone') }}</p>
      <pre v-else class="json" data-testid="unknown-json">{{ pretty(unknown) }}</pre>
    </section>

    <div class="row">
      <Button variant="primary" type="submit" :disabled="busy">{{ busy ? t('saving') : t('save') }}</Button>
      <span class="muted" role="status">{{ status }}</span>
    </div>
  </form>
</template>

<style scoped>
h2 {
  margin: 0;
  font-size: 1.05rem;
}
.check {
  display: flex;
  gap: 0.6rem;
  align-items: flex-start;
}
.check > span {
  display: grid;
}
.check input {
  margin-top: 0.3rem;
}
.field {
  display: grid;
  gap: 0.3rem;
}
.field label {
  font-weight: 600;
}
.hint {
  margin: 0;
  font-size: 0.875rem;
}
.error {
  margin: 0;
  color: var(--danger);
  font-size: 0.875rem;
}
.mono,
.json {
  font-family: var(--mono);
}
.json {
  margin: 0;
  padding: 0.6rem;
  background: var(--surface-2);
  border-radius: 6px;
  overflow: auto;
}
</style>
