<script setup lang="ts">
import { onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useTenantsStore } from '../stores/tenants'
import { useI18n } from 'vue-i18n'
import Banner from '../ui/Banner.vue'

const { t } = useI18n()

// /admin/ leads to the first tenant's home.
const tenants = useTenantsStore()
const router = useRouter()

onMounted(() => {
  const first = tenants.first()
  if (first) void router.replace({ name: 'home', params: { tenant: first.name } })
})
</script>

<template>
  <Banner v-if="tenants.error" kind="error">{{ tenants.error }}</Banner>
  <p v-else-if="tenants.list.length === 0" class="muted">{{ t('noTenants') }}</p>
  <p v-else class="muted">{{ t('loading') }}</p>
</template>
