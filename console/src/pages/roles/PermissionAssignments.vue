<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Permission, ResourceServer, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import Pager from './Pager.vue'
const props = defineProps<{ tenant: SystemTenant; kind: 'roles' | 'users'; id: string }>()
const { t } = useI18n(),
  { api } = useServices()
const permissions = ref<Permission[]>([]),
  servers = ref<ResourceServer[]>([]),
  page = ref(0),
  total = ref(0),
  loading = ref(true),
  busy = ref(false),
  error = ref(''),
  actionError = ref(''),
  audience = ref(''),
  permissionName = ref('')
const selected = computed(() => servers.value.find((s) => s.identifier === audience.value))
let epoch = 0,
  seq = 0
async function load() {
  const mine = ++seq,
    current = epoch
  loading.value = true
  error.value = ''
  try {
    const result = await api.listPermissions(props.tenant, props.kind, props.id, { page: page.value, per_page: 20 })
    if (mine !== seq || current !== epoch) return
    permissions.value = result.permissions
    total.value = result.total
  } catch (e) {
    if (mine === seq && current === epoch) error.value = errorMessage(e)
  } finally {
    if (mine === seq && current === epoch) loading.value = false
  }
}
watch(
  () => [props.tenant.host, props.kind, props.id],
  () => {
    const current = ++epoch
    ++seq
    page.value = 0
    permissions.value = []
    servers.value = []
    audience.value = ''
    permissionName.value = ''
    actionError.value = ''
    busy.value = false
    void load()
    void api
      .allResourceServers(props.tenant)
      .then((result) => {
        if (current === epoch) servers.value = result.filter((s) => !s.is_system)
      })
      .catch((e) => {
        if (current === epoch) actionError.value = errorMessage(e)
      })
  },
  { immediate: true },
)
watch(audience, () => {
  permissionName.value = ''
})
onBeforeUnmount(() => {
  ++epoch
  ++seq
})
function goto(next: number) {
  page.value = next
  void load()
}
async function change(method: 'POST' | 'DELETE', p?: Permission) {
  if (busy.value) return
  const key = p ?? { resource_server_identifier: audience.value, permission_name: permissionName.value }
  if (!key.resource_server_identifier || !key.permission_name) return
  const current = epoch
  busy.value = true
  actionError.value = ''
  try {
    await api.changePermissions(props.tenant, props.kind, props.id, method, [
      { resource_server_identifier: key.resource_server_identifier, permission_name: key.permission_name },
    ])
    if (current !== epoch) return
    await load()
  } catch (e) {
    if (current === epoch) actionError.value = errorMessage(e) + ' ' + t('rbac.uncertain')
  } finally {
    if (current === epoch) busy.value = false
  }
}
function direct(p: Permission) {
  return props.kind === 'roles' || p.sources?.some((s) => s.source_type === 'DIRECT')
}
</script>
<template>
  <div class="stack">
    <p class="muted">{{ t('rbac.expiry') }}</p>
    <Banner v-if="actionError" kind="error"
      >{{ actionError }} <Button @click="load">{{ t('rbac.reload') }}</Button></Banner
    >
    <form class="card stack" @submit.prevent="change('POST')">
      <Field id="permission-api" :label="t('rbac.api')"
        ><select id="permission-api" v-model="audience">
          <option value="">{{ t('rbac.chooseAPI') }}</option>
          <option v-for="s in servers" :key="s.id" :value="s.identifier">{{ s.name || s.identifier }}</option>
        </select></Field
      ><Field id="permission-name" :label="t('rbac.permission')"
        ><select id="permission-name" v-model="permissionName" :disabled="!selected">
          <option value="">{{ t('rbac.choosePermission') }}</option>
          <option v-for="scope in selected?.scopes ?? []" :key="scope.value" :value="scope.value">
            {{ scope.value }} — {{ scope.description }}
          </option>
        </select></Field
      ><Button type="submit" :disabled="busy || !permissionName">{{ t('rbac.addPermission') }}</Button>
    </form>
    <Banner v-if="error" kind="error"
      >{{ error }} <Button @click="load">{{ t('retry') }}</Button></Banner
    >
    <p v-else-if="loading" role="status">{{ t('loading') }}</p>
    <template v-else
      ><p v-if="permissions.length === 0" class="card empty">{{ t('rbac.noPermissions') }}</p>
      <table v-else class="data">
        <thead>
          <tr>
            <th scope="col">{{ t('rbac.api') }}</th>
            <th scope="col">{{ t('rbac.permission') }}</th>
            <th v-if="kind === 'users'" scope="col">{{ t('rbac.sources') }}</th>
            <th scope="col">
              <span class="visually-hidden">{{ t('userd.actions') }}</span>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="p in permissions" :key="p.resource_server_identifier + ' ' + p.permission_name">
            <td>{{ p.resource_server_name || p.resource_server_identifier }}</td>
            <td>
              <code>{{ p.permission_name }}</code>
              <p class="muted">{{ p.description }}</p>
            </td>
            <td v-if="kind === 'users'">
              <ul>
                <li v-for="(source, index) in p.sources" :key="index">
                  <span v-if="source.source_type === 'DIRECT'">{{ t('rbac.direct') }}</span
                  ><RouterLink v-else :to="{ name: 'role', params: { tenant: tenant.name, id: source.source_id } }">{{
                    source.source_name || t('rbac.inherited')
                  }}</RouterLink>
                </li>
              </ul>
            </td>
            <td>
              <Button v-if="direct(p)" variant="danger" :disabled="busy" @click="change('DELETE', p)">{{
                t(kind === 'users' ? 'rbac.removeDirect' : 'rbac.removePermission')
              }}</Button
              ><span v-else class="muted">{{ t('rbac.inheritedHint') }}</span>
            </td>
          </tr>
        </tbody>
      </table>
      <Pager :page="page" :total="total" :busy="busy" @change="goto"
    /></template>
  </div>
</template>
