<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import Field from '../../ui/Field.vue'
import type { QuotaDraft } from './quota'
defineProps<{ id: string; label: string; lockEnabled?: boolean; tenantDefault?: boolean }>()
const draft = defineModel<QuotaDraft>({ required: true })
const { t } = useI18n()
</script>
<template>
  <fieldset class="stack min-w-0"><legend>{{ label }}</legend>
    <p class="muted m-0">{{ t(tenantDefault ? 'rt48.defaultQuotaHint' : 'rt48.quotaHint') }}</p>
    <label class="check"><input :id="id + '-enabled'" v-model="draft.enabled" type="checkbox" :disabled="lockEnabled" /> {{ t(tenantDefault ? 'rt48.configureDefault' : 'rt48.overrideQuota') }}</label>
    <template v-if="draft.enabled">
      <label class="check"><input :id="id + '-enforce'" v-model="draft.enforce" type="checkbox" /> {{ t('rt48.enforce') }}</label>
      <div class="grid gap-4 sm:grid-cols-2">
        <Field :id="id + '-hour'" :label="t('rt48.hour')"><input :id="id + '-hour'" v-model="draft.hour" type="text" inputmode="numeric" /></Field>
        <Field :id="id + '-day'" :label="t('rt48.day')"><input :id="id + '-day'" v-model="draft.day" type="text" inputmode="numeric" /></Field>
      </div>
    </template>
  </fieldset>
</template>
