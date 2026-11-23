<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { SystemTenant, UserGroup } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
const props = defineProps<{ tenant: SystemTenant; userId: string }>(),
  { t } = useI18n(),
  { api } = useServices()
const groups = ref<UserGroup[]>([]),
  loading = ref(true),
  error = ref('')
let seq = 0
async function load() {
  const mine = ++seq
  loading.value = true
  error.value = ''
  try {
    const result = await api.listUserGroups(props.tenant, props.userId)
    if (mine === seq) groups.value = result.groups
  } catch (e) {
    if (mine === seq) error.value = errorMessage(e)
  } finally {
    if (mine === seq) loading.value = false
  }
}
watch(() => [props.tenant.host, props.userId], load, { immediate: true })
</script>
<template>
  <div class="stack">
    <Banner v-if="error" kind="error"
      >{{ error }} <Button @click="load">{{ t('retry') }}</Button></Banner
    >
    <p v-else-if="loading" role="status">{{ t('loading') }}</p>
    <p v-else-if="groups.length === 0" class="card empty">{{ t('groups.noUserGroups') }}</p>
    <ul v-else class="card">
      <li v-for="g in groups" :key="g.id">
        <RouterLink :to="{ name: 'group', params: { tenant: tenant.name, id: g.id } }">{{ g.name }}</RouterLink> <span class="muted">{{ t('groups.member') }} {{ g.membership_created_at }}</span>
      </li>
    </ul>
  </div>
</template>
