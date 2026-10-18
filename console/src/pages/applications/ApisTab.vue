<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import type { Client, ClientGrant, ResourceServer, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import { t } from '../../strings'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import GrantForm from '../apis/GrantForm.vue'

// The APIs an application may request tokens for (its client grants),
// each with its permissions, and a way to authorize another.
const props = defineProps<{ tenant: SystemTenant; client: Client }>()
const { api } = useServices()

const servers = ref<ResourceServer[]>([])
const grants = ref<ClientGrant[]>([])
const loading = ref(true)
const error = ref('')
const actionError = ref('')
const chosen = ref('')
const busy = ref(false)

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [s, g] = await Promise.all([api.allResourceServers(props.tenant), api.allClientGrants(props.tenant, { client_id: props.client.client_id })])
    servers.value = s
    grants.value = g.filter((x) => x.subject_type === 'client')
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    loading.value = false
  }
}
onMounted(load)

const rows = computed(() => grants.value.map((g) => ({ grant: g, server: servers.value.find((s) => s.identifier === g.audience) })))
const unauthorized = computed(() => servers.value.filter((s) => !grants.value.some((g) => g.audience === s.identifier)))

function label(s: ResourceServer): string {
  return s.name ? `${s.name} (${s.identifier})` : s.identifier
}

async function authorize() {
  if (!chosen.value) return
  busy.value = true
  actionError.value = ''
  try {
    const g = await api.createClientGrant(props.tenant, { client_id: props.client.client_id, audience: chosen.value, subject_type: 'client', scope: [] })
    grants.value = [...grants.value, g]
    chosen.value = ''
  } catch (e) {
    actionError.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}

async function revoke(g: ClientGrant) {
  actionError.value = ''
  try {
    await api.deleteClientGrant(props.tenant, g.id)
    grants.value = grants.value.filter((x) => x.id !== g.id)
  } catch (e) {
    actionError.value = errorMessage(e)
  }
}

function replaced(g: ClientGrant) {
  grants.value = grants.value.map((x) => (x.id === g.id ? g : x))
}
</script>

<template>
  <div class="stack">
    <p class="muted">{{ t.grants.hint }}</p>
    <Banner v-if="error" kind="error">
      {{ error }}
      <Button variant="ghost" @click="load">{{ t.retry }}</Button>
    </Banner>
    <p v-else-if="loading" class="muted" role="status">{{ t.loading }}</p>
    <template v-else>
      <Banner v-if="actionError" kind="error">{{ actionError }}</Banner>
      <div v-if="rows.length === 0" class="card"><p>{{ t.grants.empty }}</p></div>
      <ul v-else class="stack rows">
        <li v-for="r in rows" :key="r.grant.id" class="card stack" :data-testid="'grant-' + r.grant.audience">
          <div class="row item">
            <div>
              <strong v-if="r.server">
                <RouterLink :to="{ name: 'api', params: { tenant: tenant.name, id: r.server.id } }">{{ r.server.name || t.apis.unnamed }}</RouterLink>
              </strong>
              <strong v-else>{{ t.grants.unknownApi }}</strong>
              <code class="id">{{ r.grant.audience }}</code>
            </div>
            <Button variant="danger" :aria-label="t.grants.revoke + ' ' + r.grant.audience" @click="revoke(r.grant)">{{ t.grants.revoke }}</Button>
          </div>
          <GrantForm v-if="r.server" :tenant="tenant" :api="r.server" :grant="r.grant" @saved="replaced" />
        </li>
      </ul>

      <form class="card stack" novalidate @submit.prevent="authorize">
        <h2>{{ t.grants.authorizeAnother }}</h2>
        <p v-if="unauthorized.length === 0" class="muted">{{ t.grants.noneLeft }}</p>
        <template v-else>
          <Field id="grant-api" :label="t.grants.authorizeLabel">
            <select id="grant-api" v-model="chosen">
              <option value="">{{ t.grants.choose }}</option>
              <option v-for="s in unauthorized" :key="s.id" :value="s.identifier">{{ label(s) }}</option>
            </select>
          </Field>
          <div class="row">
            <Button variant="primary" type="submit" :disabled="busy || !chosen">{{ t.grants.authorize }}</Button>
          </div>
        </template>
      </form>
    </template>
  </div>
</template>

<style scoped>
.rows {
  list-style: none;
  padding: 0;
  margin: 0;
}
.item {
  justify-content: space-between;
}
.id {
  margin-left: 0.6rem;
}
h2 {
  margin: 0;
  font-size: 1.05rem;
}
</style>
