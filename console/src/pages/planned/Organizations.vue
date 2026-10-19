<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import Button from '../../ui/Button.vue'
import PlannedPage from './PlannedPage.vue'
import PreviewTable from './PreviewTable.vue'

const { t } = useI18n()
</script>

<template>
  <PlannedPage section-key="organizations">
    <template #actions>
      <Button variant="primary" disabled>{{ t('plannedPreview.organizations.create') }}</Button>
    </template>
    <PreviewTable :columns="[t('plannedPreview.organizations.name'), t('plannedPreview.organizations.displayName')]" :empty="t('plannedPreview.organizations.empty')" />
  </PlannedPage>
</template>
