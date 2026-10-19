<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import Button from '../../ui/Button.vue'
import PlannedPage from './PlannedPage.vue'
import PreviewTable from './PreviewTable.vue'

const { t } = useI18n()
</script>

<template>
  <PlannedPage section-key="roles">
    <template #actions>
      <Button variant="primary" disabled>{{ t('plannedPreview.roles.create') }}</Button>
    </template>
    <PreviewTable :columns="[t('plannedPreview.roles.name'), t('plannedPreview.roles.description')]" :empty="t('plannedPreview.roles.empty')" />
  </PlannedPage>
</template>
