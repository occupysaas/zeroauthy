<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import type { Client, Connection, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import { t } from '../../strings'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'

// The connections this application may sign users in with: one switch per
// connection, changed through the connection's clients endpoint.
const props = defineProps<{ tenant: SystemTenant; client: Client }>()
const { api } = useServices()

const connections = ref<Connection[]>([])
const enabled = reactive<Record<string, boolean>>({})
const loading = ref(true)
const error = ref('')
const rowError = reactive<Record<string, string>>({})
const busy = reactive<Record<string, boolean>>({})

async function load() {
  loading.value = true
  error.value = ''
  try {
    const list = await api.allConnections(props.tenant)
    const sets = await Promise.all(list.map((c) => api.allConnectionClients(props.tenant, c.id)))
    list.forEach((c, i) => (enabled[c.id] = sets[i]!.includes(props.client.client_id)))
    connections.value = list
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    loading.value = false
  }
}
onMounted(load)

async function toggle(c: Connection, status: boolean) {
  busy[c.id] = true
  rowError[c.id] = ''
  try {
    await api.updateConnectionClients(props.tenant, c.id, [{ client_id: props.client.client_id, status }])
    enabled[c.id] = status
  } catch (e) {
    rowError[c.id] = errorMessage(e)
    enabled[c.id] = !status
  } finally {
    busy[c.id] = false
  }
}
</script>

<template>
  <div class="stack">
    <p class="muted">{{ t.appConns.hint }}</p>
    <Banner v-if="error" kind="error">
      {{ error }}
      <Button variant="ghost" @click="load">{{ t.retry }}</Button>
    </Banner>
    <p v-else-if="loading" class="muted" role="status">{{ t.loading }}</p>
    <div v-else-if="connections.length === 0" class="card empty">
      <p>{{ t.appConns.empty }}</p>
      <RouterLink :to="{ name: 'connection-new', params: { tenant: tenant.name } }">{{ t.conns.create }}</RouterLink>
    </div>
    <ul v-else class="stack rows">
      <li v-for="c in connections" :key="c.id" class="card stack" :data-testid="'conn-' + c.id">
        <div class="row item">
          <RouterLink :to="{ name: 'connection', params: { tenant: tenant.name, id: c.id } }">{{ c.name }}</RouterLink>
          <label class="switch">
            <input
              type="checkbox"
              role="switch"
              :checked="enabled[c.id]"
              :disabled="busy[c.id]"
              :aria-label="t.appConns.enableSwitch(c.name ?? c.id)"
              @change="toggle(c, ($event.target as HTMLInputElement).checked)"
            />
            <span>{{ t.conns.enabled }}</span>
          </label>
        </div>
        <Banner v-if="rowError[c.id]" kind="error">{{ rowError[c.id] }}</Banner>
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
.switch {
  display: flex;
  gap: 0.4rem;
  align-items: center;
}
.empty p {
  margin: 0.25rem 0;
}
</style>
