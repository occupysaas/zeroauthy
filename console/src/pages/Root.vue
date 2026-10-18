<script setup lang="ts">
import { onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useServices } from '../context'
import { t } from '../strings'
import Banner from '../ui/Banner.vue'

// /admin/ leads to the first tenant's home.
const { tenants } = useServices()
const router = useRouter()

onMounted(() => {
  const first = tenants.first()
  if (first) void router.replace({ name: 'home', params: { tenant: first.name } })
})
</script>

<template>
  <Banner v-if="tenants.state.error" kind="error">{{ tenants.state.error }}</Banner>
  <p v-else-if="tenants.state.list.length === 0" class="muted">{{ t.noTenants }}</p>
  <p v-else class="muted">{{ t.loading }}</p>
</template>
