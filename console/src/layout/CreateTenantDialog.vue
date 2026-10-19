<script setup lang="ts">
import { ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { errorMessage, useServices } from '../context'
import { useTenantsStore } from '../stores/tenants'
import { useI18n } from 'vue-i18n'
import Banner from '../ui/Banner.vue'
import Button from '../ui/Button.vue'
import Field from '../ui/Field.vue'
import Modal from '../ui/Modal.vue'

const { t } = useI18n()

const open = defineModel<boolean>('open', { required: true })
const { api } = useServices()
const tenants = useTenantsStore()
const router = useRouter()
const name = ref('')
const domains = ref('')
const error = ref('')
const busy = ref(false)

watch(open, (v) => {
  if (v) {
    name.value = ''
    domains.value = ''
    error.value = ''
  }
})

async function submit() {
  busy.value = true
  error.value = ''
  try {
    const list = domains.value
      .split(/\s+/)
      .map((d) => d.trim())
      .filter(Boolean)
    const created = await tenants.create(api, { name: name.value.trim(), ...(list.length ? { domains: list } : {}) })
    open.value = false
    await router.push({ name: 'home', params: { tenant: created.name } })
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <Modal v-model:open="open" :title="t('createTenant')">
    <form class="stack" novalidate @submit.prevent="submit">
      <Banner v-if="error" kind="error">{{ error }}</Banner>
      <Field id="tenant-name" :label="t('tenantName')" :hint="t('tenantNameHint')">
        <input
          id="tenant-name"
          v-model="name"
          type="text"
          required
          autocomplete="off"
          spellcheck="false"
          pattern="[a-z0-9]([a-z0-9-]*[a-z0-9])?"
          maxlength="63"
          aria-describedby="tenant-name-hint"
        />
      </Field>
      <Field id="tenant-domains" :label="t('tenantDomains')" :hint="t('tenantDomainsHint')">
        <textarea id="tenant-domains" v-model="domains" spellcheck="false" aria-describedby="tenant-domains-hint" />
      </Field>
      <div class="row">
        <Button variant="primary" type="submit" :disabled="busy || !name.trim()">{{ busy ? t('creating') : t('create') }}</Button>
        <Button @click="open = false">{{ t('cancel') }}</Button>
      </div>
    </form>
  </Modal>
</template>
