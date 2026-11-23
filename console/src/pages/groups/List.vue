<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Group } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import { onModalClosed } from '../../ui/routeModal'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import Pager from '../roles/Pager.vue'
const { t } = useI18n(),
  { api } = useServices(),
  tenant = useTenant()
const groups = ref<Group[]>([]),
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
    const result = await api.listGroups(tn, { page: page.value, per_page: 20, search: applied.value })
    if (mine !== seq) return
    groups.value = result.groups
    total.value = result.total ?? result.groups.length
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
    groups.value = []
    void load()
  },
  { immediate: true },
)
function goto(next: number) {
  page.value = next
  void load()
}
function search() {
  applied.value = filter.value.trim()
  goto(0)
}
onBeforeUnmount(() => {
  ++seq
})
onModalClosed(load)
</script>
<template>
  <div v-if="tenant" class="stack">
    <h1>{{ t('groups.title') }}</h1>
    <form class="row" @submit.prevent="search">
      <Field id="group-filter" :label="t('groups.search')"><input id="group-filter" v-model="filter" type="search" maxlength="256" /></Field
      ><Button type="submit">{{ t('groups.search') }}</Button>
    </form>
    <Banner v-if="error" kind="error"
      >{{ error }} <Button @click="load">{{ t('retry') }}</Button></Banner
    >
    <p v-else-if="loading" role="status">{{ t('loading') }}</p>
    <template v-else
      ><p v-if="groups.length === 0" class="card empty">{{ t('groups.empty') }}</p>
      <table v-else class="data">
        <thead>
          <tr>
            <th scope="col">{{ t('groups.name') }}</th>
            <th scope="col">{{ t('groups.connection') }}</th>
            <th scope="col">{{ t('groups.externalId') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="group in groups" :key="group.id">
            <td>
              <RouterLink :to="{ name: 'group', params: { tenant: tenant.name, id: group.id } }">{{ group.name }}</RouterLink>
            </td>
            <td><code>{{ group.connection_id }}</code></td>
            <td>{{ group.external_id }}</td>
          </tr>
        </tbody>
      </table>
      <Pager :page="page" :total="total" @change="goto"
    /></template>
    <RouterView />
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
