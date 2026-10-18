<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import type { Client, Connection, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import { t } from '../../strings'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'

// A switch per application. Enabled applications change only through the
// clients endpoint, never through enabled_clients on PATCH.
const props = defineProps<{ tenant: SystemTenant; connection: Connection }>()
const { api } = useServices()

const clients = ref<Client[]>([])
const enabled = ref<string[]>([])
const loading = ref(true)
const error = ref('')
const rowError = reactive<Record<string, string>>({})
const busy = reactive<Record<string, boolean>>({})

async function load() {
  loading.value = true
  error.value = ''
  try {
    const all: Client[] = []
    for (let p = 0; ; p++) {
      const r = await api.listClients(props.tenant, { page: p, per_page: 100 })
      all.push(...r.clients)
      if (r.clients.length === 0 || all.length >= r.total) break
    }
    clients.value = all
    enabled.value = await api.allConnectionClients(props.tenant, props.connection.id)
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    loading.value = false
  }
}
onMounted(load)

const on = computed(() => new Set(enabled.value))

async function toggle(c: Client, status: boolean) {
  busy[c.client_id] = true
  rowError[c.client_id] = ''
  try {
    await api.updateConnectionClients(props.tenant, props.connection.id, [{ client_id: c.client_id, status }])
    enabled.value = status ? [...enabled.value, c.client_id] : enabled.value.filter((x) => x !== c.client_id)
  } catch (e) {
    rowError[c.client_id] = errorMessage(e)
  } finally {
    busy[c.client_id] = false
  }
}
</script>

<template>
  <div class="stack">
    <p class="muted">{{ t.conns.clientsHint }}</p>
    <Banner v-if="error" kind="error">
      {{ error }}
      <Button variant="ghost" @click="load">{{ t.retry }}</Button>
    </Banner>
    <p v-else-if="loading" class="muted" role="status">{{ t.loading }}</p>
    <div v-else-if="clients.length === 0" class="card empty">
      <p>{{ t.conns.noApps }}</p>
      <RouterLink :to="{ name: 'application-new', params: { tenant: tenant.name } }">{{ t.apis.machineCreate }}</RouterLink>
    </div>
    <ul v-else class="stack rows">
      <li v-for="c in clients" :key="c.client_id" class="card stack" :data-testid="'app-' + c.client_id">
        <div class="row item">
          <div>
            <RouterLink :to="{ name: 'application', params: { tenant: tenant.name, id: c.client_id } }">{{ c.name }}</RouterLink>
            <code class="id">{{ c.client_id }}</code>
          </div>
          <label class="switch">
            <input
              type="checkbox"
              role="switch"
              :checked="on.has(c.client_id)"
              :disabled="busy[c.client_id]"
              :aria-label="t.conns.enableSwitch(c.name)"
              @change="toggle(c, ($event.target as HTMLInputElement).checked)"
            />
            <span>{{ t.conns.enabled }}</span>
          </label>
        </div>
        <Banner v-if="rowError[c.client_id]" kind="error">{{ rowError[c.client_id] }}</Banner>
      </li>
    </ul>
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
.switch {
  display: flex;
  gap: 0.4rem;
  align-items: center;
}
.empty p {
  margin: 0.25rem 0;
}
</style>
