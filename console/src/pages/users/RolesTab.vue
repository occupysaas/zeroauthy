<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Role, SystemTenant, User } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import Pager from '../roles/Pager.vue'
const props = defineProps<{ tenant: SystemTenant; user: User }>(),
  { t } = useI18n(),
  { api } = useServices()
const roles = ref<Role[]>([]),
  choices = ref<Role[]>([]),
  page = ref(0),
  total = ref(0),
  choicePage = ref(0),
  choiceTotal = ref(0),
  selected = ref(''),
  filter = ref(''),
  loading = ref(true),
  busy = ref(false),
  error = ref(''),
  actionError = ref('')
let epoch = 0,
  seq = 0,
  choiceSeq = 0
async function load() {
  const mine = ++seq,
    current = epoch
  loading.value = true
  error.value = ''
  try {
    const result = await api.listUserRoles(props.tenant, props.user.user_id ?? '', { page: page.value, per_page: 20 })
    if (current !== epoch || mine !== seq) return
    roles.value = result.roles
    total.value = result.total
  } catch (e) {
    if (current === epoch && mine === seq) error.value = errorMessage(e)
  } finally {
    if (current === epoch && mine === seq) loading.value = false
  }
}
async function loadChoices() {
  const mine = ++choiceSeq,
    current = epoch
  try {
    const result = await api.listRoles(props.tenant, { page: choicePage.value, per_page: 20, name_filter: filter.value })
    if (current !== epoch || mine !== choiceSeq) return
    choices.value = result.roles
    choiceTotal.value = result.total
  } catch (e) {
    if (current === epoch && mine === choiceSeq) actionError.value = errorMessage(e)
  }
}
watch(
  () => [props.tenant.host, props.user.user_id],
  () => {
    ++epoch
    ++seq
    ++choiceSeq
    page.value = 0
    choicePage.value = 0
    selected.value = ''
    roles.value = []
    choices.value = []
    actionError.value = ''
    busy.value = false
    void load()
    void loadChoices()
  },
  { immediate: true },
)
onBeforeUnmount(() => {
  ++epoch
  ++seq
  ++choiceSeq
})
function goto(next: number) {
  page.value = next
  void load()
}
function search() {
  choicePage.value = 0
  void loadChoices()
}
async function change(method: 'POST' | 'DELETE', id = selected.value) {
  if (!id || busy.value) return
  const current = epoch
  busy.value = true
  actionError.value = ''
  try {
    await api.changeUserRoles(props.tenant, props.user.user_id ?? '', method, [id])
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
    <section class="card stack">
      <form class="row" @submit.prevent="search">
        <Field id="assign-role-filter" :label="t('rbac.roleSearch')"><input id="assign-role-filter" v-model="filter" type="search" /></Field
        ><Button type="submit">{{ t('rbac.filter') }}</Button>
      </form>
      <form class="row" @submit.prevent="change('POST')">
        <Field id="assign-role" :label="t('rbac.assignRole')"
          ><select id="assign-role" v-model="selected">
            <option value="">{{ t('rbac.chooseRole') }}</option>
            <option v-for="role in choices" :key="role.id" :value="role.id">{{ role.name }}</option>
          </select></Field
        ><Button type="submit" :disabled="busy || !selected">{{ t('rbac.assignRole') }}</Button>
      </form>
      <Pager
        v-if="choiceTotal > 20"
        :page="choicePage"
        :total="choiceTotal"
        @change="
          choicePage = $event;
          loadChoices()
        "
      />
    </section>
    <Banner v-if="error" kind="error"
      >{{ error }} <Button @click="load">{{ t('retry') }}</Button></Banner
    >
    <p v-else-if="loading" role="status">{{ t('loading') }}</p>
    <template v-else
      ><p v-if="roles.length === 0" class="card empty">{{ t('rbac.noRoles') }}</p>
      <table v-else class="data">
        <thead>
          <tr>
            <th scope="col">{{ t('rbac.name') }}</th>
            <th scope="col">{{ t('rbac.description') }}</th>
            <th scope="col">
              <span class="visually-hidden">{{ t('userd.actions') }}</span>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="role in roles" :key="role.id">
            <td>
              <RouterLink :to="{ name: 'role', params: { tenant: tenant.name, id: role.id } }">{{ role.name }}</RouterLink>
            </td>
            <td>{{ role.description }}</td>
            <td>
              <Button variant="danger" :disabled="busy" @click="change('DELETE', role.id)">{{ t('rbac.removeRole') }}</Button>
            </td>
          </tr>
        </tbody>
      </table>
      <Pager :page="page" :total="total" :busy="busy" @change="goto"
    /></template>
  </div>
</template>
