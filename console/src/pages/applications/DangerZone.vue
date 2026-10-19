<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import type { Client, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import Modal from '../../ui/Modal.vue'

const { t } = useI18n()

const props = defineProps<{ tenant: SystemTenant; client: Client }>()
const emit = defineEmits<{ rotated: [Client] }>()
const { api } = useServices()
const router = useRouter()

const confirmRotate = ref(false)
const confirmDelete = ref(false)
const typed = ref('')
const error = ref('')
const busy = ref(false)
const status = ref('')

async function rotate() {
  busy.value = true
  error.value = ''
  try {
    const c = await api.rotateSecret(props.tenant, props.client.client_id)
    confirmRotate.value = false
    status.value = t('apps.rotated')
    emit('rotated', c)
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}

async function remove() {
  busy.value = true
  error.value = ''
  try {
    await api.deleteClient(props.tenant, props.client.client_id)
    confirmDelete.value = false
    await router.push({ name: 'applications', params: { tenant: props.tenant.name } })
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="card stack danger-zone">
    <Banner v-if="error && !confirmRotate && !confirmDelete" kind="error">{{ error }}</Banner>
    <p v-if="status" role="status">{{ status }}</p>
    <div v-if="client.token_endpoint_auth_method !== 'none'" class="row item">
      <div>
        <strong>{{ t('apps.rotate') }}</strong>
        <p class="muted">{{ t('apps.rotateBody') }}</p>
      </div>
      <Button variant="danger" @click="(error = ''), (confirmRotate = true)">{{ t('apps.rotate') }}</Button>
    </div>
    <div class="row item">
      <div>
        <strong>{{ t('apps.deleteApp') }}</strong>
        <p class="muted">{{ t('apps.deleteBody', { name: client.name }) }}</p>
      </div>
      <Button variant="danger" @click="(error = ''), (typed = ''), (confirmDelete = true)">{{ t('apps.deleteApp') }}</Button>
    </div>

    <Modal v-model:open="confirmRotate" :title="t('apps.rotateConfirm')" :description="t('apps.rotateBody')">
      <Banner v-if="error" kind="error">{{ error }}</Banner>
      <div class="row">
        <Button variant="danger" :disabled="busy" @click="rotate">{{ t('apps.rotate') }}</Button>
        <Button @click="confirmRotate = false">{{ t('cancel') }}</Button>
      </div>
    </Modal>

    <Modal v-model:open="confirmDelete" :title="t('apps.deleteConfirm')" :description="t('apps.deleteBody', { name: client.name })">
      <form class="stack" novalidate @submit.prevent="typed === client.name && remove()">
        <Banner v-if="error" kind="error">{{ error }}</Banner>
        <Field id="delete-confirm" :label="t('apps.deleteLabel')">
          <input id="delete-confirm" v-model="typed" type="text" autocomplete="off" spellcheck="false" />
        </Field>
        <div class="row">
          <Button variant="danger" type="submit" :disabled="busy || typed !== client.name">
            {{ busy ? t('apps.deleting') : t('apps.deleteApp') }}
          </Button>
          <Button @click="confirmDelete = false">{{ t('cancel') }}</Button>
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
