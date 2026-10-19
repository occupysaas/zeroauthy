<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import Toggle from '../../ui/Toggle.vue'
import PlannedPage from './PlannedPage.vue'

const { t } = useI18n()
</script>

<template>
  <PlannedPage section-key="mfa">
    <section class="my-3 grid gap-3 rounded border border-rule bg-surface p-4" aria-labelledby="mfa-factors">
      <h2 id="mfa-factors" class="m-0">{{ t('plannedPreview.mfa.factors') }}</h2>
      <Toggle :label="t('plannedPreview.mfa.otp')" disabled />
      <Toggle :label="t('plannedPreview.mfa.push')" disabled />
      <Toggle :label="t('plannedPreview.mfa.sms')" disabled />
      <Toggle :label="t('plannedPreview.mfa.voice')" disabled />
      <Toggle :label="t('plannedPreview.mfa.email')" disabled />
      <Toggle :label="t('plannedPreview.mfa.webauthnRoaming')" disabled />
      <Toggle :label="t('plannedPreview.mfa.webauthnPlatform')" disabled />
      <Toggle :label="t('plannedPreview.mfa.recovery')" disabled />
    </section>
    <fieldset class="my-3 grid gap-2 rounded border border-rule bg-surface p-4">
      <legend class="font-bold">{{ t('plannedPreview.mfa.policy') }}</legend>
      <label class="flex items-center gap-2"><input type="radio" name="mfa-policy" disabled />{{ t('plannedPreview.mfa.never') }}</label>
      <label class="flex items-center gap-2"><input type="radio" name="mfa-policy" disabled />{{ t('plannedPreview.mfa.always') }}</label>
      <label class="flex items-center gap-2"><input type="radio" name="mfa-policy" disabled />{{ t('plannedPreview.mfa.adaptive') }}</label>
    </fieldset>
  </PlannedPage>
</template>
