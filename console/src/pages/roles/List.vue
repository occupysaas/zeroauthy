<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Role } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import Pager from './Pager.vue'
const { t } = useI18n(),
  { api } = useServices(),
  tenant = useTenant()
const roles = ref<Role[]>([]),
  total = ref(0),
  page = ref(0),
  filter = ref(''),
  applied = ref(''),
  loading = ref(true),
  error = ref('')
let seq = 0
async function load() {
  const mine = ++seq,
    tn = tenant.value
  if (!tn) {
    loading.value = false
    return
  }
  loading.value = true
  error.value = ''
  try {
    const result = await api.listRoles(tn, { page: page.value, per_page: 20, name_filter: applied.value })
    if (mine !== seq) return
    roles.value = result.roles
    total.value = result.total
  } catch (e) {
    if (mine === seq) error.value = errorMessage(e)
  } finally {
    if (mine === seq) loading.value = false
  }
}
watch(
  tenant,
  () => {
    page.value = 0
    roles.value = []
    void load()
  },
  { immediate: true },
)
function goto(next: number) {
  page.value = next
  void load()
}
function search() {
  applied.value = filter.value
  goto(0)
}
onBeforeUnmount(() => {
  ++seq
})
</script>
<template>
  <div v-if="tenant" class="stack">
    <div class="row">
      <h1>{{ t('rbac.title') }}</h1>
      <span class="flex-1" /><RouterLink :to="{ name: 'role-new', params: { tenant: tenant.name } }">{{ t('rbac.create') }}</RouterLink>
    </div>
    <form class="row" @submit.prevent="search">
      <Field id="role-filter" :label="t('rbac.filter')"><input id="role-filter" v-model="filter" type="search" /></Field
      ><Button type="submit">{{ t('rbac.filter') }}</Button>
    </form>
    <Banner v-if="error" kind="error"
      >{{ error }} <Button @click="load">{{ t('retry') }}</Button></Banner
    >
    <p v-else-if="loading" role="status">{{ t('loading') }}</p>
    <template v-else
      ><p v-if="roles.length === 0" class="card empty">{{ t('rbac.empty') }}</p>
      <table v-else class="data">
        <thead>
          <tr>
            <th scope="col">{{ t('rbac.name') }}</th>
            <th scope="col">{{ t('rbac.description') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="role in roles" :key="role.id">
            <td>
              <RouterLink :to="{ name: 'role', params: { tenant: tenant.name, id: role.id } }">{{ role.name }}</RouterLink>
            </td>
            <td>{{ role.description }}</td>
          </tr>
        </tbody>
      </table>
      <Pager :page="page" :total="total" @change="goto"
    /></template>
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
