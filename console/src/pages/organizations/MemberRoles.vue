<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Role, SystemTenant } from '../../api/client'
import { useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import Pager from '../roles/Pager.vue'
import { usePanel } from './context'
const props = defineProps<{ tenant: SystemTenant; organizationId: string; userId: string }>(), { t } = useI18n(), { api } = useServices()
const roles = ref<Role[]>([]), page = ref(0), total = ref(0), roleId = ref('')
const { loading, error, busy, reloadRequired, load, change } = usePanel(() => [props.tenant.host, props.organizationId, props.userId], () => api.listOrganizationMemberRoles(props.tenant, props.organizationId, props.userId, page.value), r => { roles.value = r.roles; total.value = r.total }, () => { roles.value = []; page.value = 0; roleId.value = '' })
function goto(next: number) { page.value = next; void load() }
function assign(method: 'POST' | 'DELETE', id = roleId.value) {
  if (!id || (method === 'POST' && total.value >= 50)) return
  void change(() => api.changeOrganizationMemberRoles(props.tenant, props.organizationId, props.userId, method, [id]))
}
</script>
<template>
  <div class="stack"><p>{{ t('orgs.roleLimit') }}</p><Banner v-if="error" kind="error">{{ error }} <Button :disabled="busy" @click="load">{{ t('retry') }}</Button></Banner><Banner v-if="reloadRequired" kind="error">{{ t('orgs.uncertain') }}</Banner>
    <form class="row" @submit.prevent="assign('POST')"><Field id="organization-role-id" :label="t('orgs.roleID')"><input id="organization-role-id" v-model="roleId" required /></Field><Button type="submit" :disabled="busy || reloadRequired || !roleId || total >= 50">{{ t('orgs.assignRole') }}</Button></form>
    <p v-if="loading" role="status">{{ t('loading') }}</p><template v-else><p v-if="!roles.length">{{ t('orgs.noRoles') }}</p><div v-for="role in roles" :key="role.id" class="row"><span>{{ role.name }}</span><code>{{ role.id }}</code><Button variant="danger" :disabled="busy || reloadRequired" @click="assign('DELETE', role.id)">{{ t('orgs.removeRole') }}</Button></div><Pager :page="page" :total="total" :busy="busy" @change="goto" /></template>
  </div>
</template>
