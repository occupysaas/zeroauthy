<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import { useActionContext } from './context'
const tabs = [{ name: 'editor', label: 'actions.editor' }, { name: 'versions', label: 'actions.versions' }, { name: 'test', label: 'actions.test' }]
import { useRoute } from 'vue-router'
const route = useRoute()
const { t } = useI18n(), { tenant, id } = useActionContext()
</script>
<template>
  <nav v-if="tenant" class="row flex-wrap" :aria-label="t('actions.navigation')">
    <RouterLink :to="{ name: 'actions', params: { tenant: tenant.name } }">{{ t('actions.library') }}</RouterLink>
    <RouterLink :to="{ name: 'action-triggers', params: { tenant: tenant.name } }">{{ t('actions.triggers') }}</RouterLink>
    <RouterLink :to="{ name: 'action-execution', params: { tenant: tenant.name } }">{{ t('actions.execution') }}</RouterLink>
    <RouterLink :to="{ name: 'action-modules', params: { tenant: tenant.name } }">{{ t('actions.modules') }}</RouterLink>
    <template v-if="id && !String(route.name).startsWith('action-module')">
      <RouterLink v-for="tab in tabs" :key="tab.name" :to="{ name: 'action-' + tab.name, params: { tenant: tenant.name, id } }">{{ t(tab.label) }}</RouterLink>
    </template>
  </nav>
</template>
