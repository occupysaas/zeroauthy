<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import type { ResourceServer, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import Modal from '../../ui/Modal.vue'

const { t } = useI18n()

const props = defineProps<{ tenant: SystemTenant; server: ResourceServer }>()
const { api } = useServices()
const router = useRouter()

const open = ref(false)
const typed = ref('')
const error = ref('')
const busy = ref(false)
// The name is what the operator types; an unnamed API uses its identifier.
const confirmWith = computed(() => props.server.name || props.server.identifier)

async function remove() {
  busy.value = true
  error.value = ''
  try {
    await api.deleteResourceServer(props.tenant, props.server.id)
    open.value = false
    await router.push({ name: 'apis', params: { tenant: props.tenant.name } })
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="card stack danger-zone">
    <div class="row item">
      <div>
        <strong>{{ t('apis.deleteApi') }}</strong>
        <p class="muted">{{ t('apis.deleteSummary') }}</p>
      </div>
      <Button variant="danger" @click="(error = ''), (typed = ''), (open = true)">{{ t('apis.deleteApi') }}</Button>
    </div>

    <Modal v-model:open="open" :title="t('apis.deleteConfirm')" :description="t('apis.deleteBody', { confirmWith })">
      <form class="stack" novalidate @submit.prevent="typed === confirmWith && remove()">
        <Banner v-if="error" kind="error">{{ error }}</Banner>
        <Field id="delete-confirm" :label="t('apis.deleteLabel')">
          <input id="delete-confirm" v-model="typed" type="text" autocomplete="off" spellcheck="false" />
        </Field>
        <div class="row">
          <Button variant="danger" type="submit" :disabled="busy || typed !== confirmWith">{{ busy ? t('apis.deleting') : t('apis.deleteApi') }}</Button>
          <Button @click="open = false">{{ t('cancel') }}</Button>
        </div>
      </form>
    </Modal>
  </div>
</template>

<style scoped>
.danger-zone {
  border-color: var(--danger);
}
.item {
  justify-content: space-between;
  flex-wrap: nowrap;
}
.item p {
  margin: 0.2rem 0 0;
}
</style>
