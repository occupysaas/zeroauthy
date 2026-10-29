<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { OrganizationMember, SystemTenant, User } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import Pager from '../roles/Pager.vue'
import MemberRoles from './MemberRoles.vue'
import { usePanel } from './context'
const props = defineProps<{ tenant: SystemTenant; organizationId: string }>(), { t } = useI18n(), { api } = useServices()
const members = ref<OrganizationMember[]>([]), users = ref<User[]>([]), query = ref(''), userPage = ref(0), userTotal = ref(0), searching = ref(false), searchError = ref(''), searchQuery = ref(''), page = ref(0), total = ref(0), selected = ref('')
let searchSeq = 0
const { loading, error, busy, reloadRequired, load, change, capture, current } = usePanel(() => [props.tenant.host, props.organizationId], () => api.listOrganizationMembers(props.tenant, props.organizationId, page.value), r => { members.value = r.members; total.value = r.total }, () => { ++searchSeq; searching.value = false; searchError.value = ''; query.value = ''; searchQuery.value = ''; users.value = []; members.value = []; page.value = 0; userPage.value = 0; userTotal.value = 0; selected.value = '' })
function goto(next: number) { page.value = next; void load() }
async function search(next = 0) {
  const mine = capture(), seq = ++searchSeq
  userPage.value = next; searching.value = true; searchError.value = ''
  if (next === 0) searchQuery.value = query.value
  try {
    const result = await api.listUsers(props.tenant, { q: searchQuery.value, page: next, per_page: 20 })
    if (current(mine) && seq === searchSeq) { users.value = result.users; userTotal.value = result.total }
  } catch (e) { if (current(mine) && seq === searchSeq) searchError.value = errorMessage(e) }
  finally { if (current(mine) && seq === searchSeq) searching.value = false }
}
async function membership(method: 'POST' | 'DELETE', userId: string) {
  const mine = capture()
  await change(() => api.changeOrganizationMembers(props.tenant, props.organizationId, method, [userId]), async () => { if (method === 'DELETE' && selected.value === userId) selected.value = ''; await load() })
  if (current(mine) && !reloadRequired.value && method === 'POST') users.value = users.value.filter(u => u.user_id !== userId)
}
</script>
<template>
  <div class="stack"><p>{{ t('orgs.membershipHint') }}</p>
    <Banner v-if="error" kind="error">{{ error }} <Button :disabled="busy" @click="load">{{ t('retry') }}</Button></Banner><Banner v-if="reloadRequired" kind="error">{{ t('orgs.uncertain') }}</Banner>
    <form class="card row" @submit.prevent="search()"><Field id="organization-user-search" :label="t('orgs.userSearch')"><input id="organization-user-search" v-model="query" type="search" /></Field><Button type="submit" :disabled="searching">{{ t('orgs.search') }}</Button></form>
    <Banner v-if="searchError" kind="error">{{ searchError }}</Banner><p v-if="searching" role="status">{{ t('loading') }}</p>
    <div v-for="user in users" :key="user.user_id" class="card row"><span>{{ user.name || user.email || user.user_id }}</span><code>{{ user.user_id }}</code><Button :disabled="busy || reloadRequired || members.some(m => m.user_id === user.user_id)" @click="membership('POST', user.user_id!)">{{ t('orgs.addMember') }}</Button></div>
    <Pager v-if="userTotal" :page="userPage" :total="userTotal" :busy="searching" @change="search" />
    <p v-if="loading" role="status">{{ t('loading') }}</p><template v-else><p v-if="!members.length">{{ t('orgs.noMembers') }}</p>
      <div v-for="member in members" :key="member.user_id" class="card row"><RouterLink :to="{ name: 'user', params: { tenant: tenant.name, id: member.user_id } }">{{ member.name || member.email || member.user_id }}</RouterLink><code>{{ member.user_id }}</code><Button :disabled="busy" @click="selected = member.user_id!">{{ t('orgs.memberRoles') }}</Button><Button variant="danger" :disabled="busy || reloadRequired" @click="membership('DELETE', member.user_id!)">{{ t('orgs.removeMember') }}</Button></div>
      <Pager :page="page" :total="total" :busy="busy" @change="goto" />
    </template>
    <section v-if="selected" class="card stack"><h2>{{ t('orgs.memberRoles') }}: {{ selected }}</h2><Button @click="selected = ''">{{ t('close') }}</Button><MemberRoles :tenant="tenant" :organization-id="organizationId" :user-id="selected" /></section>
  </div>
</template>
