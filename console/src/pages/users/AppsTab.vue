<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { SystemTenant, User, UserGrant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'

const { t } = useI18n()
const props = defineProps<{ tenant: SystemTenant; user: User }>()
const { api } = useServices()

const grants = ref<UserGrant[]>([])
const loading = ref(true)
const error = ref('')
const actionError = ref('')

async function load() {
  loading.value = true
  error.value = ''
  try {
    grants.value = await api.listUserGrants(props.tenant, props.user.user_id ?? '')
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    loading.value = false
  }
}
onMounted(load)

async function revoke(g: UserGrant) {
  actionError.value = ''
  try {
    await api.deleteGrant(props.tenant, g.id)
    grants.value = grants.value.filter((x) => x.id !== g.id)
  } catch (e) {
    actionError.value = errorMessage(e)
  }
}
</script>

<template>
  <div class="stack">
    <Banner v-if="error" kind="error">
      {{ error }}
      <Button variant="ghost" @click="load">{{ t('retry') }}</Button>
    </Banner>
    <p v-else-if="loading" class="muted" role="status">{{ t('loading') }}</p>
    <div v-else-if="grants.length === 0" class="card empty">
      <p>{{ t('userd.noGrants') }}</p>
    </div>
    <template v-else>
      <Banner v-if="actionError" kind="error">{{ actionError }}</Banner>
      <table class="data">
        <thead>
          <tr>
            <th scope="col">{{ t('userd.application') }}</th>
            <th scope="col">{{ t('userd.api') }}</th>
            <th scope="col">{{ t('userd.scopes') }}</th>
            <th scope="col"><span class="visually-hidden">{{ t('userd.actions') }}</span></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="g in grants" :key="g.id">
            <td><code>{{ g.clientID }}</code></td>
            <td>{{ g.audience }}</td>
            <td>{{ g.scope.join(' ') }}</td>
            <td><Button variant="danger" :aria-label="t('userd.revokeAccess', { client: g.clientID, api: g.audience })" @click="revoke(g)">{{ t('userd.revoke') }}</Button></td>
          </tr>
        </tbody>
      </table>
    </template>
  </div>
</template>
