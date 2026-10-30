<script setup lang="ts">
import { TabsContent, TabsList, TabsRoot, TabsTrigger } from 'reka-ui'
import { onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import { ApiError, type Role } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import RouteModal from '../../ui/RouteModal.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import ConfirmDialog from '../../ui/ConfirmDialog.vue'
import PermissionsTab from './PermissionsTab.vue'
import UsersTab from './UsersTab.vue'
const { t } = useI18n(),
  { api } = useServices(),
  tenant = useTenant(),
  route = useRoute(),
  router = useRouter()
const role = ref<Role | null>(null),
  name = ref(''),
  description = ref(''),
  tab = ref('settings'),
  error = ref(''),
  actionError = ref(''),
  status = ref(''),
  busy = ref(false),
  notFound = ref(false),
  deleteOpen = ref(false),
  deleteCount = ref<number | null>(null),
  deleteError = ref('')
let epoch = 0,
  seq = 0
async function load() {
  const mine = ++seq,
    current = epoch,
    tn = tenant.value,
    id = route.params.id
  if (!tn || typeof id !== 'string') return
  error.value = ''
  notFound.value = false
  try {
    const result = await api.getRole(tn, id)
    if (mine !== seq || current !== epoch) return
    role.value = result
    name.value = result.name
    description.value = result.description
  } catch (e) {
    if (mine !== seq || current !== epoch) return
    if (e instanceof ApiError && e.status === 404) notFound.value = true
    else error.value = errorMessage(e)
  }
}
watch(
  [tenant, () => route.params.id],
  () => {
    ++epoch
    ++seq
    role.value = null
    name.value = ''
    description.value = ''
    actionError.value = ''
    status.value = ''
    busy.value = false
    deleteOpen.value = false
    deleteCount.value = null
    tab.value = 'settings'
    void load()
  },
  { immediate: true },
)
onBeforeUnmount(() => {
  ++epoch
  ++seq
})
async function save() {
  const tn = tenant.value,
    current = epoch,
    id = role.value?.id
  if (!tn || !id || busy.value) return
  if (!name.value.trim()) {
    actionError.value = t('rbac.roleRequired')
    return
  }
  busy.value = true
  actionError.value = ''
  status.value = ''
  try {
    const result = await api.updateRole(tn, id, { name: name.value, description: description.value })
    if (current !== epoch) return
    role.value = result
    status.value = t('saved')
  } catch (e) {
    if (current === epoch) actionError.value = errorMessage(e) + ' ' + t('rbac.uncertain')
  } finally {
    if (current === epoch) busy.value = false
  }
}
async function confirmDelete() {
  const tn = tenant.value,
    current = epoch,
    id = role.value?.id
  if (!tn || !id || busy.value) return
  deleteOpen.value = true
  deleteCount.value = null
  deleteError.value = ''
  try {
    const result = await api.listRoleUsers(tn, id, { page: 0, per_page: 1 })
    if (current === epoch) deleteCount.value = result.total
  } catch (e) {
    if (current === epoch) deleteError.value = errorMessage(e)
  }
}
async function remove() {
  const tn = tenant.value,
    current = epoch,
    id = role.value?.id
  if (!tn || !id || busy.value) return
  busy.value = true
  deleteError.value = ''
  try {
    await api.deleteRole(tn, id)
    if (current === epoch) await router.push({ name: 'roles', params: { tenant: tn.name } })
  } catch (e) {
    if (current === epoch) deleteError.value = errorMessage(e) + ' ' + t('rbac.uncertain')
  } finally {
    if (current === epoch) busy.value = false
  }
}
</script>
<template>
  <RouteModal v-if="tenant" :title="role?.name ?? t('rbac.title')" back="roles" wide>
    <Banner v-if="notFound" kind="error">{{ t('notFoundBody') }}</Banner
    ><Banner v-else-if="error" kind="error"
      >{{ error }} <Button @click="load">{{ t('retry') }}</Button></Banner
    >
    <p v-else-if="!role" role="status">{{ t('loading') }}</p>
    <template v-else>
      <code>{{ role.id }}</code
      ><TabsRoot v-model="tab"
        ><TabsList class="tabs" :aria-label="role.name"
          ><TabsTrigger class="tab" value="settings">{{ t('rbac.settings') }}</TabsTrigger
          ><TabsTrigger class="tab" value="permissions">{{ t('rbac.permissions') }}</TabsTrigger
          ><TabsTrigger class="tab" value="users">{{ t('rbac.users') }}</TabsTrigger></TabsList
        ><TabsContent value="settings"
          ><form class="card stack" @submit.prevent="save">
            <Banner v-if="actionError" kind="error"
              >{{ actionError }} <Button @click="load">{{ t('rbac.reload') }}</Button></Banner
            ><Field id="role-name" :label="t('rbac.name')"><input id="role-name" v-model="name" required maxlength="128" /></Field
            ><Field id="role-description" :label="t('rbac.description')">
              <textarea id="role-description" v-model="description" maxlength="255" />
            </Field>
            <div class="row">
              <Button type="submit" variant="primary" :disabled="busy">{{ t('save') }}</Button
              ><span role="status">{{ status }}</span>
            </div>
          </form>
          <section class="card stack mt-4">
            <p class="muted">{{ t('rbac.expiry') }}</p>
            <Button variant="danger" :disabled="busy" @click="confirmDelete">{{ t('rbac.delete') }}</Button>
          </section></TabsContent
        ><TabsContent value="permissions"><PermissionsTab :tenant="tenant" :role-id="role.id" /></TabsContent
        ><TabsContent value="users"><UsersTab :tenant="tenant" :role-id="role.id" /></TabsContent></TabsRoot></template
    ><ConfirmDialog
      v-model:open="deleteOpen"
      :title="t('rbac.deleteTitle')"
      :description="deleteCount === null ? t('loading') : t('rbac.deleteHint', { count: deleteCount })"
      :confirm-label="t('rbac.delete')"
      :busy="busy"
      :disabled="deleteCount === null"
      :error="deleteError"
      @confirm="remove"
    />
  </RouteModal>
</template>
