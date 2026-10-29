<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Organization, SystemTenant } from '../../api/client'
import { useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Pager from '../roles/Pager.vue'
import { usePanel } from '../organizations/context'
const props = defineProps<{ tenant: SystemTenant; userId: string }>(), { t } = useI18n(), { api } = useServices()
const organizations = ref<Organization[]>([]), page = ref(0), total = ref(0)
const { loading, error, load } = usePanel(() => [props.tenant.host, props.userId], () => api.listOrganizations(props.tenant, page.value, props.userId), r => { organizations.value = r.organizations; total.value = r.total }, () => { organizations.value = []; page.value = 0 })
function goto(next: number) { page.value = next; void load() }
</script>
<template>
  <div class="stack"><Banner v-if="error" kind="error">{{ error }} <Button @click="load">{{ t('retry') }}</Button></Banner><p v-else-if="loading" role="status">{{ t('loading') }}</p><template v-else><p v-if="!organizations.length">{{ t('orgs.empty') }}</p><div v-for="org in organizations" :key="org.id" class="card row"><RouterLink :to="{ name: 'organization', params: { tenant: tenant.name, id: org.id } }">{{ org.display_name }}</RouterLink><code>{{ org.name }}</code></div><Pager :page="page" :total="total" @change="goto" /></template></div>
</template>
