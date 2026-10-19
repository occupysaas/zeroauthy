<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ApiError, type Client } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'

const { t } = useI18n()

const NAME = /^[a-zA-Z0-9](-[a-zA-Z0-9]|[a-zA-Z0-9])*$/

const { api } = useServices()
const tenant = useTenant()
const router = useRouter()
const name = ref('')
const errors = reactive<Record<string, string>>({})
const general = ref('')
const busy = ref(false)
const clients = ref<Client[]>([])
const chosen = ref<string[]>([])
const clientsError = ref('')

// Enabled applications may be sent on create (and only there).
onMounted(async () => {
  const tn = tenant.value
  if (!tn) return
  try {
    const all: Client[] = []
    for (let p = 0; ; p++) {
      const r = await api.listClients(tn, { page: p, per_page: 100 })
      all.push(...r.clients)
      if (r.clients.length === 0 || all.length >= r.total) break
    }
    clients.value = all
  } catch (e) {
    clientsError.value = errorMessage(e)
  }
})

function validate(): boolean {
  for (const k of Object.keys(errors)) delete errors[k]
  const n = name.value.trim()
  if (!n) errors.name = t('conns.nameRequired')
  else if (n.length > 128) errors.name = t('conns.nameTooLong')
  else if (!NAME.test(n)) errors.name = t('conns.nameInvalid')
  return Object.keys(errors).length === 0
}

async function submit() {
  const tn = tenant.value
  general.value = ''
  if (!tn || !validate()) return
  busy.value = true
  try {
    const c = await api.createConnection(tn, { name: name.value.trim(), strategy: 'auth0', enabled_clients: chosen.value })
    await router.push({ name: 'connection', params: { tenant: tn.name, id: c.id } })
  } catch (e) {
    if (e instanceof ApiError && e.errorCode === 'connection_conflict') errors.name = e.message
    else general.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div v-if="tenant">
    <RouterLink :to="{ name: 'connections', params: { tenant: tenant.name } }">← {{ t('conns.back') }}</RouterLink>
    <h1>{{ t('conns.createTitle') }}</h1>
    <form class="card stack" novalidate @submit.prevent="submit">
      <Banner v-if="general" kind="error">{{ general }}</Banner>
      <Field id="conn-name" :label="t('conns.name')" :hint="t('conns.nameHint')" :error="errors.name">
        <input id="conn-name" v-model="name" type="text" maxlength="128" autocomplete="off" spellcheck="false" :aria-invalid="!!errors.name" :aria-describedby="'conn-name-hint' + (errors.name ? ' conn-name-error' : '')" />
      </Field>
      <Field id="conn-strategy" :label="t('conns.strategy')" :hint="t('conns.strategyHint')">
        <input id="conn-strategy" :value="t('conns.strategies.auth0')" type="text" readonly aria-describedby="conn-strategy-hint" />
      </Field>
      <fieldset class="stack apps">
        <legend>{{ t('conns.enableOnCreate') }}</legend>
        <p class="muted">{{ t('conns.enableOnCreateHint') }}</p>
        <Banner v-if="clientsError" kind="error">{{ clientsError }}</Banner>
        <p v-else-if="clients.length === 0" class="muted">{{ t('conns.noApps') }}</p>
        <label v-for="c in clients" :key="c.client_id" class="check">
          <input v-model="chosen" type="checkbox" :value="c.client_id" />
          <span>{{ c.name }}</span>
        </label>
      </fieldset>
      <div class="row">
        <Button variant="primary" type="submit" :disabled="busy">{{ busy ? t('creating') : t('conns.createSubmit') }}</Button>
      </div>
    </form>
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>

<style scoped>
.apps {
  border: 0;
  padding: 0;
  margin: 0;
}
.apps legend {
  font-weight: 600;
  padding: 0;
}
.check {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}
</style>
