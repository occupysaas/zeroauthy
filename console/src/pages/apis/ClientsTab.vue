<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import type { Client, ClientGrant, ResourceServer, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import GrantForm from './GrantForm.vue'

const { t } = useI18n()

// Every machine-to-machine application of the tenant, with a switch that
// authorizes it for this API and, once on, its permissions.
const props = defineProps<{ tenant: SystemTenant; server: ResourceServer }>()
const { api } = useServices()

const clients = ref<Client[]>([])
const grants = ref<ClientGrant[]>([])
const loading = ref(true)
const error = ref('')
const rowError = reactive<Record<string, string>>({})
const busy = reactive<Record<string, boolean>>({})

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [c, g] = await Promise.all([api.allMachineClients(props.tenant), api.allClientGrants(props.tenant, { audience: props.server.identifier })])
    clients.value = c
    grants.value = g.filter((x) => x.subject_type === 'client')
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    loading.value = false
  }
}
onMounted(load)

const byClient = computed(() => new Map(grants.value.map((g) => [g.client_id, g])))

async function toggle(c: Client, on: boolean) {
  busy[c.client_id] = true
  rowError[c.client_id] = ''
  try {
    const existing = byClient.value.get(c.client_id)
    if (on && !existing) {
      const g = await api.createClientGrant(props.tenant, { client_id: c.client_id, audience: props.server.identifier, subject_type: 'client', scope: [] })
      grants.value = [...grants.value, g]
    } else if (!on && existing) {
      await api.deleteClientGrant(props.tenant, existing.id)
      grants.value = grants.value.filter((g) => g.id !== existing.id)
    }
  } catch (e) {
    rowError[c.client_id] = errorMessage(e)
  } finally {
    busy[c.client_id] = false
  }
}

function replaced(g: ClientGrant) {
  grants.value = grants.value.map((x) => (x.id === g.id ? g : x))
}
</script>

<template>
  <div class="stack">
    <p class="muted">{{ t('apis.machineHint') }}</p>
    <Banner v-if="error" kind="error">
      {{ error }}
      <Button variant="ghost" @click="load">{{ t('retry') }}</Button>
    </Banner>
    <p v-else-if="loading" class="muted" role="status">{{ t('loading') }}</p>
    <div v-else-if="clients.length === 0" class="card empty [&_p]:my-1">
      <p>{{ t('apis.machineEmpty') }}</p>
      <RouterLink :to="{ name: 'application-new', params: { tenant: tenant.name } }">{{ t('apis.machineCreate') }}</RouterLink>
    </div>
    <ul v-else class="stack m-0 list-none p-0">
      <li v-for="c in clients" :key="c.client_id" class="card stack" :data-testid="'m2m-' + c.client_id">
        <div class="row justify-between">
          <div>
            <RouterLink :to="{ name: 'application', params: { tenant: tenant.name, id: c.client_id } }">{{ c.name }}</RouterLink>
            <code class="ml-2.5">{{ c.client_id }}</code>
          </div>
          <label class="flex items-center gap-1.5">
            <input
              type="checkbox"
              role="switch"
              :checked="byClient.has(c.client_id)"
              :disabled="busy[c.client_id]"
              :aria-label="t('apis.authorizeSwitch', { name: c.name })"
              @change="toggle(c, ($event.target as HTMLInputElement).checked)"
            />
            <span>{{ t('apis.authorized') }}</span>
          </label>
        </div>
        <Banner v-if="rowError[c.client_id]" kind="error">{{ rowError[c.client_id] }}</Banner>
        <section v-if="byClient.get(c.client_id)" :aria-label="t('apis.permissionsOf', { name: c.name })">
          <GrantForm :tenant="tenant" :api="server" :grant="byClient.get(c.client_id)!" @saved="replaced" />
        </section>
      </li>
    </ul>
  </div>
</template>
