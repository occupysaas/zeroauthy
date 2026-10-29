<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Organization } from '../../api/client'
import { useServices, useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import Pager from '../roles/Pager.vue'
import { usePanel } from './context'
const { t } = useI18n(), { api } = useServices(), tenant = useTenant()
const organizations = ref<Organization[]>([]), page = ref(0), total = ref(0), filter = ref('')
const { loading, error, load } = usePanel(() => tenant.value?.host, async () => tenant.value ? api.listOrganizations(tenant.value, page.value) : { organizations: [], total: 0 }, r => { organizations.value = r.organizations; total.value = r.total }, () => { organizations.value = []; page.value = 0; filter.value = '' })
const visible = computed(() => organizations.value.filter(o => o.name.includes(filter.value.toLowerCase())))
function goto(next: number) { page.value = next; void load() }
</script>
<template>
  <div v-if="tenant" class="stack">
    <div class="row"><h1>{{ t('orgs.title') }}</h1><span class="flex-1" /><RouterLink :to="{ name: 'organization-new', params: { tenant: tenant.name } }">{{ t('orgs.create') }}</RouterLink></div>
    <Field id="organization-filter" :label="t('orgs.filter')"><input id="organization-filter" v-model="filter" type="search" /></Field>
    <Banner v-if="error" kind="error">{{ error }} <Button @click="load">{{ t('retry') }}</Button></Banner>
    <p v-else-if="loading" role="status">{{ t('loading') }}</p>
    <template v-else><p v-if="!visible.length" class="card empty">{{ t('orgs.empty') }}</p>
      <table v-else class="data"><thead><tr><th>{{ t('orgs.name') }}</th><th>{{ t('orgs.displayName') }}</th></tr></thead><tbody><tr v-for="org in visible" :key="org.id"><td><RouterLink :to="{ name: 'organization', params: { tenant: tenant.name, id: org.id } }">{{ org.name }}</RouterLink></td><td>{{ org.display_name }}</td></tr></tbody></table>
      <Pager :page="page" :total="total" @change="goto" />
    </template>
  </div><Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
