<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import Field from '../../ui/Field.vue'
import Toggle from '../../ui/Toggle.vue'
import PlannedPage from './PlannedPage.vue'

const { t } = useI18n()
const current = ref('verifyEmail')
// Literal keys so the catalog scan sees them.
const templates = computed(() => [
  { id: 'verifyEmail', label: t('plannedPreview.emails.verifyEmail') },
  { id: 'welcome', label: t('plannedPreview.emails.welcome') },
  { id: 'changePassword', label: t('plannedPreview.emails.changePassword') },
  { id: 'blockedAccount', label: t('plannedPreview.emails.blockedAccount') },
  { id: 'passwordBreach', label: t('plannedPreview.emails.passwordBreach') },
  { id: 'mfaEnrollment', label: t('plannedPreview.emails.mfaEnrollment') },
  { id: 'userInvitation', label: t('plannedPreview.emails.userInvitation') },
])
const heading = computed(() => templates.value.find((x) => x.id === current.value)?.label)
</script>

<template>
  <PlannedPage section-key="emails">
    <div class="my-3 grid gap-4 md:grid-cols-[14rem_1fr]">
      <div data-preview-nav role="radiogroup" :aria-label="t('plannedPreview.emails.picker')" class="grid content-start gap-1">
        <button
          v-for="tpl in templates"
          :key="tpl.id"
          type="button"
          role="radio"
          :aria-checked="current === tpl.id"
          :class="['cursor-pointer rounded border-0 px-3 py-1.5 text-left font-sans', current === tpl.id ? 'bg-active font-bold text-text' : 'bg-transparent text-muted hover:bg-active']"
          @click="current = tpl.id"
        >
          {{ tpl.label }}
        </button>
      </div>
      <section class="grid max-w-xl gap-3" aria-labelledby="em-heading">
        <h2 id="em-heading" class="m-0">{{ heading }}</h2>
        <Toggle :label="t('plannedPreview.emails.enabled')" disabled />
        <Field id="em-from" :label="t('plannedPreview.emails.from')"><input id="em-from" disabled /></Field>
        <Field id="em-subject" :label="t('plannedPreview.emails.subject')"><input id="em-subject" disabled /></Field>
        <Field id="em-result" :label="t('plannedPreview.emails.resultUrl')"><input id="em-result" type="url" disabled /></Field>
        <Field id="em-life" :label="t('plannedPreview.emails.urlLifetime')" :hint="t('plannedPreview.emails.urlLifetimeHint')">
          <input id="em-life" type="number" aria-describedby="em-life-hint" disabled />
        </Field>
        <Field id="em-body" :label="t('plannedPreview.emails.body')"><textarea id="em-body" rows="8" disabled /></Field>
      </section>
    </div>
    <section class="my-3 grid max-w-xl gap-3 rounded border border-rule bg-surface p-4" aria-labelledby="em-provider">
      <h2 id="em-provider" class="m-0">{{ t('plannedPreview.emails.provider') }}</h2>
      <Field id="em-prov" :label="t('plannedPreview.emails.providerChoice')">
        <select id="em-prov" disabled><option>{{ t('plannedPreview.emails.providerNone') }}</option></select>
      </Field>
      <Field id="em-default-from" :label="t('plannedPreview.emails.defaultFrom')"><input id="em-default-from" type="email" disabled /></Field>
    </section>
  </PlannedPage>
</template>
