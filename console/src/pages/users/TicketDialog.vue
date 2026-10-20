<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import CopyButton from '../../ui/CopyButton.vue'
import Modal from '../../ui/Modal.vue'

const { t } = useI18n()
const props = defineProps<{ tenant: SystemTenant; userId: string; kind: 'password' | 'verify' }>()
const open = defineModel<boolean>('open', { required: true })
const { api } = useServices()

// The server's default lifetime, in seconds; the request does not ask for another.
const TTL_SEC = 432000
const days = TTL_SEC / 86400

// The URL lives only here, in this component: never in a store, never
// written anywhere. Closing the dialog drops it, and it cannot be shown again.
const ticket = ref('')
const error = ref('')
const busy = ref(false)

watch(open, async (isOpen) => {
  ticket.value = ''
  error.value = ''
  if (!isOpen) return
  busy.value = true
  try {
    const r = props.kind === 'password' ? await api.createPasswordChangeTicket(props.tenant, props.userId) : await api.createVerificationTicket(props.tenant, props.userId)
    if (open.value) ticket.value = r.ticket
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
})
</script>

<template>
  <Modal v-model:open="open" :title="kind === 'password' ? t('userd.resetLinkTitle') : t('userd.verifyLinkTitle')" :description="kind === 'password' ? t('userd.resetLinkBody') : t('userd.verifyLinkBody')">
    <div class="stack">
      <Banner v-if="error" kind="error">{{ error }}</Banner>
      <p v-else-if="busy" class="muted" role="status">{{ t('loading') }}</p>
      <template v-else-if="ticket">
        <code class="block break-all rounded border border-hair bg-surface px-3 py-2" data-testid="ticket-url">{{ ticket }}</code>
        <div class="row">
          <CopyButton :value="ticket" :label="t('userd.copyLink')" />
          <span class="muted">{{ t('userd.linkTtl', { n: days }) }}</span>
        </div>
        <p class="muted m-0">{{ t('userd.shownOnce') }}</p>
      </template>
      <div class="row"><Button variant="primary" @click="open = false">{{ t('done') }}</Button></div>
    </div>
  </Modal>
</template>
