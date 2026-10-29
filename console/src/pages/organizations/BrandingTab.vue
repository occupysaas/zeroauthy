<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Organization, SystemTenant } from '../../api/client'
import { useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import { usePanel } from './context'
const props = defineProps<{ tenant: SystemTenant; organizationId: string }>(), emit = defineEmits<{ saved: [Organization] }>()
const { t } = useI18n(), { api } = useServices(), logo = ref(''), primary = ref(''), background = ref('')
const hex = (v: string) => /^#(?:[\da-f]{3}|[\da-f]{6})$/i.test(v)
function apply(o: Organization) { logo.value = o.branding?.logo_url ?? ''; primary.value = o.branding?.colors?.primary ?? ''; background.value = o.branding?.colors?.page_background ?? '' }
const preview = computed(() => ({ color: hex(primary.value) ? primary.value : '#222222', backgroundColor: hex(background.value) ? background.value : '#ffffff' }))
const { loading, error, busy, status, reloadRequired, load, change, capture, current } = usePanel(() => [props.tenant.host, props.organizationId], () => api.getOrganization(props.tenant, props.organizationId), apply, () => { logo.value = ''; primary.value = ''; background.value = '' })
async function save() {
  let validURL = !logo.value
  try { if (logo.value) validURL = new URL(logo.value).protocol === 'https:' } catch { validURL = false }
  if (!validURL || ((primary.value || background.value) && (!hex(primary.value) || !hex(background.value)))) { error.value = t('orgs.invalidBranding'); return }
  const branding = { ...(logo.value ? { logo_url: logo.value } : {}), ...(primary.value ? { colors: { primary: primary.value, page_background: background.value } } : {}) }, mine = capture()
  await change(async () => {
    const result = await api.updateOrganization(props.tenant, props.organizationId, { branding })
    if (current(mine)) { apply(result); emit('saved', result); status.value = t('saved') }
  }, () => {})
}
</script>
<template>
  <div class="stack"><Banner v-if="error" kind="error">{{ error }}</Banner><Banner v-if="reloadRequired" kind="error">{{ t('orgs.uncertain') }} <Button :disabled="busy" @click="load">{{ t('orgs.reload') }}</Button></Banner>
    <p v-if="loading" role="status">{{ t('loading') }}</p><form v-else class="card stack" novalidate @submit.prevent="save">
      <p>{{ t('orgs.brandingHint') }}</p>
      <Field id="organization-logo" :label="t('orgs.logo')"><input id="organization-logo" v-model="logo" type="url" /></Field>
      <Field id="organization-primary" :label="t('orgs.primary')"><input id="organization-primary" v-model="primary" placeholder="#123456" /></Field>
      <Field id="organization-background" :label="t('orgs.background')"><input id="organization-background" v-model="background" placeholder="#ffffff" /></Field>
      <div class="card" data-testid="branding-preview" :style="preview">{{ t('orgs.preview') }}</div>
      <div class="row"><Button type="submit" variant="primary" :disabled="busy || reloadRequired">{{ t('save') }}</Button><span role="status">{{ status }}</span></div>
    </form>
  </div>
</template>
