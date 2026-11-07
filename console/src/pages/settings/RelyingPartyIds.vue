<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { ConsoleRelyingPartyId } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import { useMfaScope } from '../security/scope'
const { t } = useI18n(), { api } = useServices(), tenant = useTenant()
const { key, capture, current } = useMfaScope(() => tenant.value)
const rows = ref<ConsoleRelyingPartyId[]>([]), loading = ref(false), error = ref('')
async function load() {
  const c = capture(); rows.value = []; error.value = ''; loading.value = true
  if (!c) return
  try { const result = await api.getRelyingPartyIds(c.tenant); if (current(c)) rows.value = result }
  catch (e) { if (current(c)) error.value = errorMessage(e) }
  finally { if (current(c)) loading.value = false }
}
watch(key, load, { immediate: true, flush: 'sync' })
</script>
<template>
  <section v-if="tenant" class="stack">
    <h1>{{ t('passkeys.rpidTitle') }}</h1>
    <Banner v-if="tenant.seeded" kind="warn">{{ t('seededBanner') }}</Banner>
    <Banner kind="warn">{{ t('passkeys.rpWarning') }}</Banner>
    <Banner v-if="error" kind="error">{{ error }} <Button @click="load">{{ t('retry') }}</Button></Banner>
    <p v-if="loading" role="status">{{ t('loading') }}</p>
    <table v-else class="data"><thead><tr><th>{{ t('passkeys.host') }}</th><th>{{ t('passkeys.origin') }}</th><th>{{ t('passkeys.kind') }}</th><th>{{ t('passkeys.rpid') }}</th><th>{{ t('customDomain.status') }}</th><th>{{ t('userd.actions') }}</th></tr></thead>
      <tbody><tr v-for="row in rows" :key="row.host" :data-host="row.host"><td>{{ row.host }}</td><td>{{ row.origin }}</td><td>{{ t(`passkeys.kinds.${row.kind}`) }}</td><td>{{ row.relying_party_identifier }}</td><td :class="{ 'text-danger': !row.valid }">{{ t(row.valid ? 'passkeys.valid' : 'passkeys.invalid') }}</td><td><RouterLink v-if="row.custom_domain_id" :to="{ name: 'custom-domain', params: { tenant: tenant.name, id: row.custom_domain_id } }">{{ t('passkeys.edit') }}</RouterLink></td></tr></tbody>
    </table>
  </section>
</template>
