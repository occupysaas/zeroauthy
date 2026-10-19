<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import PlannedPage from './PlannedPage.vue'
import PreviewTable from './PreviewTable.vue'

const { t } = useI18n()
</script>

<template>
  <PlannedPage section-key="logs">
    <template #actions>
      <Button disabled>{{ t('plannedPreview.logs.streams') }}</Button>
    </template>
    <div class="my-3 flex flex-wrap gap-3">
      <Field id="logs-type" :label="t('plannedPreview.logs.type')">
        <select id="logs-type" disabled>
          <option>{{ t('plannedPreview.logs.anyType') }}</option>
        </select>
      </Field>
      <Field id="logs-from" :label="t('plannedPreview.logs.from')">
        <input id="logs-from" type="date" disabled />
      </Field>
      <Field id="logs-to" :label="t('plannedPreview.logs.to')">
        <input id="logs-to" type="date" disabled />
      </Field>
    </div>
    <PreviewTable
      :columns="[t('plannedPreview.logs.event'), t('plannedPreview.logs.description'), t('plannedPreview.logs.date'), t('plannedPreview.logs.connection'), t('plannedPreview.logs.application')]"
      :empty="t('plannedPreview.logs.empty')"
    />
  </PlannedPage>
</template>
