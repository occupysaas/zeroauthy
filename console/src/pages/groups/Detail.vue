<script setup lang="ts">
import { TabsContent, TabsList, TabsRoot, TabsTrigger } from 'reka-ui'
import { onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import { ApiError, type Group, type GroupMember, type Role } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import RouteModal from '../../ui/RouteModal.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import ConfirmDialog from '../../ui/ConfirmDialog.vue'
const { t } = useI18n(),
  { api } = useServices(),
  tenant = useTenant(),
  route = useRoute(),
  router = useRouter()
const group = ref<Group | null>(null),
  members = ref<GroupMember[]>([]),
  next = ref(''),
  roles = ref<Role[]>([]),
  roleID = ref(''),
  tab = ref('members'),
  error = ref(''),
  actionError = ref(''),
  busy = ref(false),
  notFound = ref(false),
  deleteOpen = ref(false),
  deleteError = ref('')
let epoch = 0
async function load() {
  const current = epoch,
    tn = tenant.value,
    id = route.params.id
  if (!tn || typeof id !== 'string') return
  error.value = ''
  notFound.value = false
  try {
    const [g, m, r] = await Promise.all([api.getGroup(tn, id), api.listGroupMembers(tn, id), api.listGroupRoles(tn, id)])
    if (current !== epoch) return
    group.value = g
    members.value = m.members
    next.value = m.next ?? ''
    roles.value = r.roles
  } catch (e) {
    if (current !== epoch) return
    if (e instanceof ApiError && e.status === 404) notFound.value = true
    else error.value = errorMessage(e)
  }
}
async function more() {
  const current = epoch,
    tn = tenant.value,
    id = group.value?.id
  if (!tn || !id || !next.value || busy.value) return
  busy.value = true
  try {
    const m = await api.listGroupMembers(tn, id, next.value)
    if (current !== epoch) return
    members.value = [...members.value, ...m.members]
    next.value = m.next ?? ''
  } catch (e) {
    if (current === epoch) actionError.value = errorMessage(e)
  } finally {
    if (current === epoch) busy.value = false
  }
}
watch(
  [tenant, () => route.params.id],
  () => {
    ++epoch
    group.value = null
    members.value = []
    roles.value = []
    next.value = ''
    roleID.value = ''
    actionError.value = ''
    busy.value = false
    deleteOpen.value = false
    tab.value = 'members'
    void load()
  },
  { immediate: true },
)
onBeforeUnmount(() => {
  ++epoch
})
async function changeRole(method: 'POST' | 'DELETE', id: string) {
  const tn = tenant.value,
    current = epoch,
    gid = group.value?.id
  if (!tn || !gid || !id || busy.value) return
  busy.value = true
  actionError.value = ''
  try {
    await api.changeGroupRoles(tn, gid, method, [id])
    if (current !== epoch) return
    roleID.value = ''
    roles.value = (await api.listGroupRoles(tn, gid)).roles
  } catch (e) {
    if (current === epoch) actionError.value = errorMessage(e) + ' ' + t('rbac.uncertain')
  } finally {
    if (current === epoch) busy.value = false
  }
}
async function remove() {
  const tn = tenant.value,
    current = epoch,
    id = group.value?.id
  if (!tn || !id || busy.value) return
  busy.value = true
  deleteError.value = ''
  try {
    await api.deleteGroup(tn, id)
    if (current === epoch) await router.push({ name: 'groups', params: { tenant: tn.name } })
  } catch (e) {
    if (current === epoch) deleteError.value = errorMessage(e)
  } finally {
    if (current === epoch) busy.value = false
  }
}
</script>
<template>
  <RouteModal v-if="tenant" :title="group?.name ?? t('groups.title')" back="groups" wide>
    <Banner v-if="notFound" kind="error">{{ t('notFoundBody') }}</Banner
    ><Banner v-else-if="error" kind="error"
      >{{ error }} <Button @click="load">{{ t('retry') }}</Button></Banner
    >
    <p v-else-if="!group" role="status">{{ t('loading') }}</p>
    <template v-else>
      <p>
        <code>{{ group.id }}</code> · {{ t('groups.connection') }} <code>{{ group.connection_id }}</code
        ><template v-if="group.external_id"> · {{ t('groups.externalId') }} {{ group.external_id }}</template>
      </p>
      <Banner v-if="actionError" kind="error">{{ actionError }}</Banner>
      <TabsRoot v-model="tab"
        ><TabsList class="tabs" :aria-label="group.name"
          ><TabsTrigger class="tab" value="members">{{ t('groups.members') }}</TabsTrigger
          ><TabsTrigger class="tab" value="roles">{{ t('groups.roles') }}</TabsTrigger></TabsList
        ><TabsContent value="members">
          <p v-if="members.length === 0" class="card empty">{{ t('groups.noMembers') }}</p>
          <table v-else class="data">
            <thead>
              <tr>
                <th scope="col">{{ t('groups.members') }}</th>
                <th scope="col">{{ t('groups.member') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="m in members" :key="m.id">
                <td>
                  <RouterLink :to="{ name: 'user', params: { tenant: tenant.name, id: m.id } }">{{ m.id }}</RouterLink>
                </td>
                <td>{{ m.created_at }}</td>
              </tr>
            </tbody>
          </table>
          <Button v-if="next" class="mt-3" :disabled="busy" @click="more">{{ t('groups.more') }}</Button></TabsContent
        ><TabsContent value="roles">
          <p class="muted">{{ t('groups.rolesHint') }} {{ t('rbac.expiry') }}</p>
          <form class="card row" @submit.prevent="changeRole('POST', roleID)">
            <Field id="group-role-id" :label="t('groups.roleID')"><input id="group-role-id" v-model="roleID" required autocomplete="off" /></Field
            ><Button type="submit" :disabled="busy || !roleID">{{ t('groups.assignRole') }}</Button>
          </form>
          <p v-if="roles.length === 0" class="card empty">{{ t('groups.noRoles') }}</p>
          <table v-else class="data">
            <tbody>
              <tr v-for="r in roles" :key="r.id">
                <td>
                  <RouterLink :to="{ name: 'role', params: { tenant: tenant.name, id: r.id } }">{{ r.name }}</RouterLink>
                </td>
                <td>
                  <Button variant="danger" :disabled="busy" @click="changeRole('DELETE', r.id)">{{ t('groups.removeRole') }}</Button>
                </td>
              </tr>
            </tbody>
          </table></TabsContent
        ></TabsRoot
      >
      <section class="card stack mt-4">
        <Button variant="danger" :disabled="busy" @click="deleteOpen = true">{{ t('groups.delete') }}</Button>
      </section>
    </template>
    <ConfirmDialog
      v-model:open="deleteOpen"
      :title="t('groups.deleteTitle')"
      :description="t('groups.deleteHint')"
      :confirm-label="t('groups.delete')"
      :busy="busy"
      :error="deleteError"
      @confirm="remove"
    />
  </RouteModal>
</template>
