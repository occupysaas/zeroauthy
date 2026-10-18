<script setup lang="ts">
import { ref, watch } from 'vue'
import type { ClientGrant, ResourceServer, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import { t } from '../../strings'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import ScopePicker from './ScopePicker.vue'

// The scope picker of one grant, saved on its own.
const props = defineProps<{ tenant: SystemTenant; api: ResourceServer; grant: ClientGrant }>()
const emit = defineEmits<{ saved: [ClientGrant] }>()
const { api: client } = useServices()

const selected = ref<string[]>([])
const all = ref(false)
const busy = ref(false)
const error = ref('')
const status = ref('')

watch(
  () => props.grant,
  (g) => {
    selected.value = [...(g.scope ?? [])]
    all.value = !!g.allow_all_scopes
  },
  { immediate: true },
)

async function save() {
  busy.value = true
  error.value = ''
  status.value = ''
  try {
    const g = await client.updateClientGrant(props.tenant, props.grant.id, all.value ? { allow_all_scopes: true } : { scope: selected.value })
    status.value = t.apis.grantSaved
    emit('saved', g)
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="stack">
    <Banner v-if="error" kind="error">{{ error }}</Banner>
    <ScopePicker :id="'grant-' + grant.id" v-model:selected="selected" v-model:all="all" :scopes="api.scopes ?? []" :disabled="busy" />
    <div class="row">
      <Button variant="primary" :disabled="busy" @click="save">{{ busy ? t.saving : t.apis.grantSave }}</Button>
      <span class="muted" role="status">{{ status }}</span>
    </div>
  </div>
</template>
