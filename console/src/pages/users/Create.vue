<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ApiError, type Connection, type UserCreate } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import { checkPassword, emptyProfile, type RuleResult } from '../connections/checker'
import { policyOf, requiresUsername } from './policy'

const { t, te } = useI18n()

const EMAIL = /^[^\s@]+@[^\s@]+$/

const { api } = useServices()
const tenant = useTenant()
const router = useRouter()

const connections = ref<Connection[]>([])
const loadError = ref('')
const loaded = ref(false)
const form = reactive({ connection: '', email: '', username: '', password: '', verify: true })
const errors = reactive<Record<string, string>>({})
const general = ref('')
const busy = ref(false)

onMounted(async () => {
  const tn = tenant.value
  if (!tn) return
  try {
    connections.value = await api.allDatabaseConnections(tn)
    if (connections.value.length === 1) form.connection = connections.value[0]?.name ?? ''
  } catch (e) {
    loadError.value = errorMessage(e)
  } finally {
    loaded.value = true
  }
})

const chosen = computed(() => connections.value.find((c) => c.name === form.connection))
const needsUsername = computed(() => requiresUsername(chosen.value))
// The live checker runs in the browser; the password goes nowhere until submit.
const results = computed<RuleResult[]>(() => {
  const prof = emptyProfile()
  prof.email = form.email
  prof.username = form.username
  return checkPassword(policyOf(chosen.value), prof, form.password).filter((r) => r.checked)
})

function ruleLabel(r: RuleResult): string {
  const policy = policyOf(chosen.value)
  if (r.rule === 'length') return r.detail === 'long' ? t('conns.checker.tooLong') : t('conns.checker.minLen', { n: Number(r.detail) })
  if (r.rule === 'types') return policy.characterTypeRule === 'three_of_four' ? t('conns.checker.rules.threeOfFour') : t('conns.checker.rules.types')
  return te(`conns.checker.rules.${r.rule}`) ? t(`conns.checker.rules.${r.rule}`) : r.rule
}

function validate(): boolean {
  for (const k of Object.keys(errors)) delete errors[k]
  if (!form.connection) errors.connection = t('users.connectionRequired')
  const email = form.email.trim()
  if (!email) errors.email = t('users.emailRequired')
  else if (!EMAIL.test(email)) errors.email = t('users.emailInvalid')
  if (needsUsername.value && !form.username.trim()) errors.username = t('users.usernameRequired')
  if (!form.password) errors.password = t('users.passwordRequired')
  return Object.keys(errors).length === 0
}

async function submit() {
  const tn = tenant.value
  general.value = ''
  if (!tn || !validate()) return
  busy.value = true
  const body: UserCreate = { connection: form.connection, email: form.email.trim(), password: form.password, verify_email: form.verify }
  if (needsUsername.value) body.username = form.username.trim()
  try {
    const u = await api.createUser(tn, body)
    await router.push({ name: 'user', params: { tenant: tn.name, id: u.user_id ?? '' } })
  } catch (e) {
    // The server's own message names what it refused: show it by the field it is about.
    if (e instanceof ApiError && e.status === 409) errors.email = e.message
    else if (e instanceof ApiError && e.status === 400 && /password/i.test(e.message)) errors.password = e.message
    else general.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div v-if="tenant">
    <RouterLink :to="{ name: 'users', params: { tenant: tenant.name } }">← {{ t('users.back') }}</RouterLink>
    <h1>{{ t('users.createTitle') }}</h1>
    <Banner v-if="loadError" kind="error">{{ loadError }}</Banner>
    <Banner v-else-if="loaded && connections.length === 0" kind="info">{{ t('users.noConnections') }}</Banner>
    <form v-else class="card stack" novalidate @submit.prevent="submit">
      <Banner v-if="general" kind="error">{{ general }}</Banner>
      <Field id="user-connection" :label="t('users.connection')" :error="errors.connection">
        <select id="user-connection" v-model="form.connection" :aria-invalid="!!errors.connection" :aria-describedby="errors.connection ? 'user-connection-error' : undefined">
          <option value="" disabled>{{ t('users.connection') }}</option>
          <option v-for="c in connections" :key="c.id" :value="c.name">{{ c.name }}</option>
        </select>
      </Field>
      <Field id="user-email" :label="t('users.email')" :error="errors.email">
        <input id="user-email" v-model="form.email" type="email" autocomplete="off" spellcheck="false" :aria-invalid="!!errors.email" :aria-describedby="errors.email ? 'user-email-error' : undefined" />
      </Field>
      <Field v-if="needsUsername" id="user-username" :label="t('users.username')" :hint="t('users.usernameHint')" :error="errors.username">
        <input id="user-username" v-model="form.username" type="text" autocomplete="off" spellcheck="false" :aria-invalid="!!errors.username" :aria-describedby="'user-username-hint' + (errors.username ? ' user-username-error' : '')" />
      </Field>
      <Field id="user-password" :label="t('users.password')" :error="errors.password">
        <input id="user-password" v-model="form.password" type="password" autocomplete="new-password" :aria-invalid="!!errors.password" :aria-describedby="'user-password-rules' + (errors.password ? ' user-password-error' : '')" />
      </Field>
      <div v-if="form.connection" id="user-password-rules" class="m-0">
        <p class="m-0 font-bold">{{ t('users.passwordRules') }}</p>
        <ul class="my-1 list-none p-0" aria-live="polite">
          <li v-for="r in results" :key="r.rule" :data-rule="r.rule" :data-ok="r.ok">
            <span aria-hidden="true">{{ r.ok ? '✓' : '✗' }}</span>
            {{ ruleLabel(r) }}
            <span class="sr-only">: {{ r.ok ? t('conns.checker.pass') : t('conns.checker.fail') }}</span>
          </li>
        </ul>
        <p class="m-0 text-sm text-muted">{{ t('users.passwordRulesNote') }}</p>
      </div>
      <label class="check">
        <input v-model="form.verify" type="checkbox" />
        <span>{{ t('users.verifyEmail') }}</span>
      </label>
      <div class="row">
        <Button variant="primary" type="submit" :disabled="busy">{{ busy ? t('creating') : t('users.createSubmit') }}</Button>
      </div>
    </form>
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
