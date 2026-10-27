<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { RoleUser, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import Pager from './Pager.vue'
const props = defineProps<{ tenant: SystemTenant; roleId: string }>(),
  { t } = useI18n(),
  { api } = useServices()
const users = ref<RoleUser[]>([]),
  page = ref(0),
  total = ref(0),
  userID = ref(''),
  loading = ref(true),
  busy = ref(false),
  error = ref(''),
  actionError = ref('')
let epoch = 0,
  seq = 0
async function load() {
  const mine = ++seq,
    current = epoch
  loading.value = true
  error.value = ''
  try {
    const result = await api.listRoleUsers(props.tenant, props.roleId, { page: page.value, per_page: 20 })
    if (current !== epoch || mine !== seq) return
    users.value = result.users
    total.value = result.total
  } catch (e) {
    if (current === epoch && mine === seq) error.value = errorMessage(e)
  } finally {
    if (current === epoch && mine === seq) loading.value = false
  }
}
watch(
  () => [props.tenant.host, props.roleId],
  () => {
    ++epoch
    ++seq
    page.value = 0
    users.value = []
    userID.value = ''
    actionError.value = ''
    busy.value = false
    void load()
  },
  { immediate: true },
)
onBeforeUnmount(() => {
  ++epoch
  ++seq
})
function goto(next: number) {
  page.value = next
  void load()
}
async function change(method: 'POST' | 'DELETE', id = userID.value) {
  if (!id || busy.value) return
  const current = epoch
  busy.value = true
  actionError.value = ''
  try {
    if (method === 'POST') await api.assignRoleUsers(props.tenant, props.roleId, [id])
    else await api.changeUserRoles(props.tenant, id, 'DELETE', [props.roleId])
    if (current === epoch) await load()
  } catch (e) {
    if (current === epoch) actionError.value = errorMessage(e) + ' ' + t('rbac.uncertain')
  } finally {
    if (current === epoch) busy.value = false
  }
}
</script>
<template>
  <div class="stack">
    <p class="muted">{{ t('rbac.expiry') }}</p>
    <Banner v-if="actionError" kind="error"
      >{{ actionError }} <Button @click="load">{{ t('rbac.reload') }}</Button></Banner
    >
    <form class="card row" @submit.prevent="change('POST')">
      <Field id="role-user-id" :label="t('rbac.userID')"><input id="role-user-id" v-model="userID" required autocomplete="off" /></Field
      ><Button type="submit" :disabled="busy || !userID">{{ t('rbac.assignUser') }}</Button>
    </form>
    <Banner v-if="error" kind="error"
      >{{ error }} <Button @click="load">{{ t('retry') }}</Button></Banner
    >
    <p v-else-if="loading" role="status">{{ t('loading') }}</p>
    <template v-else
      ><p v-if="users.length === 0" class="card empty">{{ t('rbac.noUsers') }}</p>
      <table v-else class="data">
        <thead>
          <tr>
            <th scope="col">{{ t('rbac.users') }}</th>
            <th scope="col">
              <span class="visually-hidden">{{ t('userd.actions') }}</span>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="user in users" :key="user.user_id">
            <td>
              <RouterLink :to="{ name: 'user', params: { tenant: tenant.name, id: user.user_id } }">{{
                user.name || user.email || user.user_id
              }}</RouterLink>
              <p class="muted">{{ user.email }}</p>
            </td>
            <td>
              <Button variant="danger" :disabled="busy" @click="change('DELETE', user.user_id)">{{ t('rbac.removeUser') }}</Button>
            </td>
          </tr>
        </tbody>
      </table>
      <Pager :page="page" :total="total" :busy="busy" @change="goto"
    /></template>
  </div>
</template>
