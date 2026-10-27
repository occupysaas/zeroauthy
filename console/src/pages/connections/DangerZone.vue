<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import type { Connection, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import Modal from '../../ui/Modal.vue'
import { isEnterpriseConnection, isFederated } from './social/social'

const { t } = useI18n()

const props = defineProps<{ tenant: SystemTenant; connection: Connection }>()
const { api } = useServices()
const router = useRouter()

const open = ref(false)
const typed = ref('')
const error = ref('')
const busy = ref(false)

async function remove() {
  busy.value = true
  error.value = ''
  try {
    await api.deleteConnection(props.tenant, props.connection.id)
    open.value = false
    await router.push({ name: isEnterpriseConnection(props.connection) ? 'enterprise' : isFederated(props.connection) ? 'social' : 'connections', params: { tenant: props.tenant.name } })
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="card stack border-danger">
    <div class="row flex-nowrap justify-between">
      <div>
        <strong>{{ t('conns.deleteConnection') }}</strong>
        <p class="muted m-0 mt-1">{{ t('conns.deleteSummary') }}</p>
      </div>
      <Button variant="danger" @click="(error = ''), (typed = ''), (open = true)">{{ t('conns.deleteConnection') }}</Button>
    </div>

    <Modal v-model:open="open" :title="t('conns.deleteConfirm')" :description="t('conns.deleteBody', { name: connection.name ?? '' })">
      <form class="stack" novalidate @submit.prevent="typed === connection.name && remove()">
        <Banner v-if="error" kind="error">{{ error }}</Banner>
        <Field id="delete-confirm" :label="t('conns.deleteLabel')">
          <input id="delete-confirm" v-model="typed" type="text" autocomplete="off" spellcheck="false" />
        </Field>
        <div class="row">
          <Button variant="danger" type="submit" :disabled="busy || typed !== connection.name">{{ busy ? t('conns.deleting') : t('conns.deleteConnection') }}</Button>
          <Button @click="open = false">{{ t('cancel') }}</Button>
        </div>
      </form>
    </Modal>
  </div>
</template>
