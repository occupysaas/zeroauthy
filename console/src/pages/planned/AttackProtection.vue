<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import Field from '../../ui/Field.vue'
import Toggle from '../../ui/Toggle.vue'
import PlannedPage from './PlannedPage.vue'

const { t } = useI18n()
</script>

<template>
  <PlannedPage section-key="attack-protection">
    <section class="my-3 grid gap-3 rounded border border-rule bg-surface p-4" aria-labelledby="ap-brute">
      <h2 id="ap-brute" class="m-0">{{ t('plannedPreview.attack.brute') }}</h2>
      <Toggle :label="t('plannedPreview.attack.enabled')" disabled />
      <Field id="ap-brute-max" :label="t('plannedPreview.attack.maxAttempts')">
        <input id="ap-brute-max" type="number" disabled />
      </Field>
      <Toggle :label="t('plannedPreview.attack.block')" disabled />
      <Toggle :label="t('plannedPreview.attack.notify')" disabled />
      <Field id="ap-brute-allow" :label="t('plannedPreview.attack.allowList')" :hint="t('plannedPreview.attack.allowListHint')">
        <textarea id="ap-brute-allow" aria-describedby="ap-brute-allow-hint" disabled />
      </Field>
    </section>
    <section class="my-3 grid gap-3 rounded border border-rule bg-surface p-4" aria-labelledby="ap-breach">
      <h2 id="ap-breach" class="m-0">{{ t('plannedPreview.attack.breached') }}</h2>
      <Toggle :label="t('plannedPreview.attack.enabled')" disabled />
      <Toggle :label="t('plannedPreview.attack.block')" disabled />
      <Toggle :label="t('plannedPreview.attack.notify')" disabled />
      <Field id="ap-breach-freq" :label="t('plannedPreview.attack.frequency')">
        <select id="ap-breach-freq" disabled>
          <option>{{ t('plannedPreview.attack.immediately') }}</option>
          <option>{{ t('plannedPreview.attack.daily') }}</option>
          <option>{{ t('plannedPreview.attack.weekly') }}</option>
          <option>{{ t('plannedPreview.attack.monthly') }}</option>
        </select>
      </Field>
    </section>
    <section class="my-3 grid gap-3 rounded border border-rule bg-surface p-4" aria-labelledby="ap-ip">
      <h2 id="ap-ip" class="m-0">{{ t('plannedPreview.attack.suspicious') }}</h2>
      <Toggle :label="t('plannedPreview.attack.enabled')" disabled />
      <Toggle :label="t('plannedPreview.attack.block')" disabled />
      <Toggle :label="t('plannedPreview.attack.notify')" disabled />
      <Field id="ap-ip-allow" :label="t('plannedPreview.attack.allowList')" :hint="t('plannedPreview.attack.allowListHint')">
        <textarea id="ap-ip-allow" aria-describedby="ap-ip-allow-hint" disabled />
      </Field>
      <Field id="ap-ip-login" :label="t('plannedPreview.attack.loginRate')">
        <input id="ap-ip-login" type="number" disabled />
      </Field>
      <Field id="ap-ip-signup" :label="t('plannedPreview.attack.signupRate')">
        <input id="ap-ip-signup" type="number" disabled />
      </Field>
    </section>
  </PlannedPage>
</template>
