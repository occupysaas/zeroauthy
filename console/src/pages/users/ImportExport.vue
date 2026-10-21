<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import ExportForm from './ExportForm.vue'
import ImportForm from './ImportForm.vue'
import JobsList from './JobsList.vue'

const { t } = useI18n()
const tenant = useTenant()
// Bumped when a job is created, so the list reads again at once.
const refresh = ref(0)
</script>

<template>
  <div v-if="tenant" class="stack">
    <RouterLink :to="{ name: 'users', params: { tenant: tenant.name } }">{{ t('jobs.back') }}</RouterLink>
    <h1 class="m-0">{{ t('jobs.title') }}</h1>
    <div class="grid items-start gap-4 lg:grid-cols-2">
      <ImportForm :tenant="tenant" @created="refresh++" />
      <ExportForm :tenant="tenant" @created="refresh++" />
    </div>
    <JobsList :tenant="tenant" :refresh="refresh" />
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
