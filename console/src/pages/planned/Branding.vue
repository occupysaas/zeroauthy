<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import Field from '../../ui/Field.vue'
import PlannedPage from './PlannedPage.vue'

const { t } = useI18n()
</script>

<template>
  <PlannedPage section-key="branding">
    <div class="grid max-w-xl gap-3">
      <Field id="br-logo" :label="t('plannedPreview.branding.logoUrl')"><input id="br-logo" type="url" disabled /></Field>
      <Field id="br-favicon" :label="t('plannedPreview.branding.faviconUrl')"><input id="br-favicon" type="url" disabled /></Field>
      <Field id="br-primary" :label="t('plannedPreview.branding.primaryColor')">
        <input id="br-primary" type="color" value="#d7141a" disabled />
      </Field>
      <Field id="br-bg" :label="t('plannedPreview.branding.backgroundColor')">
        <input id="br-bg" type="color" value="#ffffff" disabled />
      </Field>
      <Field id="br-font" :label="t('plannedPreview.branding.fontUrl')"><input id="br-font" type="url" disabled /></Field>
    </div>
  </PlannedPage>
</template>
