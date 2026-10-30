<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ApiError, type Organization } from '../../api/client'
import { useServices, useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import { onModalClosed } from '../../ui/routeModal'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import { usePanel } from './context'
const { t } = useI18n(), { api } = useServices(), tenant = useTenant()
const organizations = ref<Organization[]>([]), filter = ref(''), parser = ref<'lucene' | 'scim'>('lucene'), from = ref(''), next = ref(''), legacy = ref(false), page = ref(0)
const { loading, error, load } = usePanel(() => tenant.value?.host, async () => {
 const tn = tenant.value, q = filter.value, syntax = parser.value, cursor = from.value, offset = page.value
 if (!tn) return { organizations: [], next: '', legacy: false }
 try { return { ...await api.searchOrganizations(tn, q, syntax, cursor || undefined), legacy: false } }
 catch (e) {
  if (!(e instanceof ApiError) || e.status !== 501 || e.errorCode !== 'organizations_ii_unavailable') throw e
  const result = await api.listOrganizations(tn, offset)
  return { organizations: result.organizations, next: (offset + 1) * 20 < result.total ? String(offset + 1) : '', legacy: true }
 }
}, r => { organizations.value = (r.organizations ?? []) as Organization[]; next.value = r.next ?? ''; legacy.value = r.legacy }, () => { organizations.value = []; from.value = ''; next.value = ''; filter.value = ''; legacy.value = false; page.value = 0 })
watch([filter, parser], () => { from.value = ''; next.value = ''; organizations.value = []; void load() })
function goto(cursor: string) { from.value = cursor; page.value = Number(cursor) || 0; void load() }
onModalClosed(load)
</script>
<template>
  <div v-if="tenant" class="stack">
    <div class="row"><h1>{{ t('orgs.title') }}</h1><span class="flex-1" /><RouterLink :to="{ name: 'organization-new', params: { tenant: tenant.name } }">{{ t('orgs.create') }}</RouterLink></div>
    <Field id="organization-filter" :label="t('orgs.filter')"><input id="organization-filter" v-model="filter" type="search" :disabled="legacy" /></Field>
    <Field id="organization-parser" :label="t('orgs.parser')"><select id="organization-parser" v-model="parser" :disabled="legacy"><option value="lucene">Lucene</option><option value="scim">SCIM</option></select></Field>
    <p v-if="legacy">{{ t('orgs.legacySearch') }}</p>
    <Banner v-if="error" kind="error">{{ error }} <Button @click="load">{{ t('retry') }}</Button></Banner>
    <p v-else-if="loading" role="status">{{ t('loading') }}</p>
    <template v-else><p v-if="!organizations.length" class="card empty">{{ t('orgs.empty') }}</p>
      <table v-else class="data"><thead><tr><th>{{ t('orgs.name') }}</th><th>{{ t('orgs.displayName') }}</th></tr></thead><tbody><tr v-for="org in organizations" :key="org.id"><td><RouterLink :to="{ name: 'organization', params: { tenant: tenant.name, id: org.id } }">{{ org.name }}</RouterLink></td><td>{{ org.display_name }}</td></tr></tbody></table>
      <div class="row"><Button :disabled="loading || !from" @click="goto('')">{{ t('orgs.firstPage') }}</Button><Button :disabled="loading || !next" @click="goto(next)">{{ t('next') }}</Button></div>
    </template>
    <RouterView />
  </div><Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
