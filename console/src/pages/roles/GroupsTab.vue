<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Group, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
const props = defineProps<{ tenant: SystemTenant; roleId: string }>(),
  { t } = useI18n(),
  { api } = useServices()
const groups = ref<Group[]>([]),
  loading = ref(true),
  error = ref('')
let seq = 0
async function load() {
  const mine = ++seq
  loading.value = true
  error.value = ''
  try {
    const result = await api.listRoleGroups(props.tenant, props.roleId)
    if (mine === seq) groups.value = result.groups
  } catch (e) {
    if (mine === seq) error.value = errorMessage(e)
  } finally {
    if (mine === seq) loading.value = false
  }
}
watch(() => [props.tenant.host, props.roleId], load, { immediate: true })
</script>
<template>
  <div class="stack">
    <Banner v-if="error" kind="error"
      >{{ error }} <Button @click="load">{{ t('retry') }}</Button></Banner
    >
    <p v-else-if="loading" role="status">{{ t('loading') }}</p>
    <p v-else-if="groups.length === 0" class="card empty">{{ t('groups.noRoleGroups') }}</p>
    <ul v-else class="card">
      <li v-for="g in groups" :key="g.id">
        <RouterLink :to="{ name: 'group', params: { tenant: tenant.name, id: g.id } }">{{ g.name }}</RouterLink>
      </li>
    </ul>
  </div>
</template>
