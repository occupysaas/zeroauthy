<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { ConnectionProfile, SelfServiceProfile } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import { onModalClosed } from '../../ui/routeModal'
const { t } = useI18n(),
  { api } = useServices(),
  tenant = useTenant()
const profiles = ref<SelfServiceProfile[]>([]),
  connProfiles = ref<ConnectionProfile[]>([]),
  name = ref(''),
  cpName = ref(''),
  cpPrefix = ref(''),
  loading = ref(true),
  busy = ref(false),
  error = ref('')
let seq = 0
async function load() {
  const mine = ++seq,
    tn = tenant.value
  if (!tn) return
  loading.value = true
  error.value = ''
  try {
    const [p, c] = await Promise.all([api.listSelfServiceProfiles(tn), api.listConnectionProfiles(tn)])
    if (mine !== seq) return
    profiles.value = p
    connProfiles.value = c.connection_profiles ?? []
  } catch (e) {
    if (mine === seq) error.value = errorMessage(e)
  } finally {
    if (mine === seq) loading.value = false
  }
}
watch(tenant, load, { immediate: true })
onModalClosed(load)
async function run(fn: () => Promise<unknown>) {
  if (busy.value) return
  busy.value = true
  error.value = ''
  try {
    await fn()
    await load()
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
const createProfile = () =>
  run(async () => {
    await api.createSelfServiceProfile(tenant.value!, { name: name.value.trim() })
    name.value = ''
  })
const createConnectionProfile = () =>
  run(async () => {
    await api.createConnectionProfile(tenant.value!, { name: cpName.value.trim(), ...(cpPrefix.value ? { connection_name_prefix_template: cpPrefix.value } : {}) })
    cpName.value = ''
    cpPrefix.value = ''
  })
const deleteConnectionProfile = (id: string) => run(() => api.deleteConnectionProfile(tenant.value!, id))
</script>
<template>
  <div v-if="tenant" class="stack">
    <h1>{{ t('ssso.title') }}</h1>
    <p class="muted">{{ t('ssso.intro') }}</p>
    <Banner v-if="error" kind="error">{{ error }}</Banner>
    <p v-if="loading" role="status">{{ t('loading') }}</p>
    <template v-else>
      <h2>{{ t('ssso.profiles') }}</h2>
      <form class="row" @submit.prevent="createProfile">
        <Field id="ssso-name" :label="t('ssso.name')"><input id="ssso-name" v-model="name" required maxlength="100" /></Field
        ><Button type="submit" :disabled="busy || !name.trim() || tenant.seeded">{{ t('ssso.create') }}</Button>
      </form>
      <p v-if="profiles.length === 0" class="card empty">{{ t('ssso.empty') }}</p>
      <table v-else class="data">
        <thead>
          <tr>
            <th scope="col">{{ t('ssso.name') }}</th>
            <th scope="col">{{ t('ssso.strategies') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="p in profiles" :key="p.id">
            <td>
              <RouterLink :to="{ name: 'self-service-profile', params: { tenant: tenant.name, id: p.id } }">{{ p.name }}</RouterLink>
            </td>
            <td>{{ (p.allowed_strategies ?? []).join(', ') }}</td>
          </tr>
        </tbody>
      </table>
      <h2>{{ t('ssso.connectionProfiles') }}</h2>
      <form class="row" @submit.prevent="createConnectionProfile">
        <Field id="cp-name" :label="t('ssso.name')"><input id="cp-name" v-model="cpName" required maxlength="50" /></Field
        ><Field id="cp-prefix" :label="t('ssso.prefix')"><input id="cp-prefix" v-model="cpPrefix" maxlength="15" placeholder="con-{org_name}" /></Field
        ><Button type="submit" :disabled="busy || !cpName.trim() || tenant.seeded">{{ t('ssso.createConnectionProfile') }}</Button>
      </form>
      <p v-if="connProfiles.length === 0" class="card empty">{{ t('ssso.noConnectionProfiles') }}</p>
      <table v-else class="data">
        <tbody>
          <tr v-for="c in connProfiles" :key="c.id">
            <td>{{ c.name }}</td>
            <td><code>{{ c.connection_name_prefix_template }}</code></td>
            <td><Button variant="danger" :disabled="busy || tenant.seeded" @click="deleteConnectionProfile(c.id!)">{{ t('ssso.remove') }}</Button></td>
          </tr>
        </tbody>
      </table>
    </template>
    <RouterView />
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
