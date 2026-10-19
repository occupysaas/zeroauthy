<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import Button from '../../ui/Button.vue'
import PlannedPage from './PlannedPage.vue'
import PreviewTable from './PreviewTable.vue'

const { t } = useI18n()
</script>

<template>
  <PlannedPage section-key="custom-domains">
    <template #actions>
      <Button variant="primary" disabled>{{ t('plannedPreview.customDomains.add') }}</Button>
    </template>
    <PreviewTable :columns="[t('plannedPreview.customDomains.domain'), t('plannedPreview.customDomains.status'), t('plannedPreview.customDomains.type')]" :empty="t('plannedPreview.customDomains.empty')" />
  </PlannedPage>
</template>
