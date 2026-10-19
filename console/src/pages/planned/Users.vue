<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import PlannedPage from './PlannedPage.vue'
import PreviewTable from './PreviewTable.vue'

const { t } = useI18n()
</script>

<template>
  <PlannedPage section-key="users">
    <template #actions>
      <Button variant="primary" disabled>{{ t('plannedPreview.users.create') }}</Button>
      <Button disabled>{{ t('plannedPreview.users.import') }}</Button>
      <Button disabled>{{ t('plannedPreview.users.resetEmails') }}</Button>
    </template>
    <div class="my-3 max-w-md">
      <Field id="users-search" :label="t('plannedPreview.users.search')" :hint="t('plannedPreview.users.searchHint')">
        <input id="users-search" type="text" disabled aria-describedby="users-search-hint" />
      </Field>
    </div>
    <PreviewTable
      :columns="[t('plannedPreview.users.name'), t('plannedPreview.users.connection'), t('plannedPreview.users.logins'), t('plannedPreview.users.lastLogin')]"
      :empty="t('plannedPreview.users.empty')"
    />
  </PlannedPage>
</template>
