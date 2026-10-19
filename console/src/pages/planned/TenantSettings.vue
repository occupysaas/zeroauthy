<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { TabsContent, TabsList, TabsRoot, TabsTrigger } from 'reka-ui'
import { locales } from '../../i18n'
import Field from '../../ui/Field.vue'
import PlannedPage from './PlannedPage.vue'

const { t } = useI18n()
const tab = ref('general')
</script>

<template>
  <PlannedPage section-key="settings">
    <TabsRoot v-model="tab">
      <div data-preview-nav>
        <TabsList class="tabs" :aria-label="t('plannedPreview.tenant.tabs')">
          <TabsTrigger class="tab" value="general">{{ t('plannedPreview.tenant.general') }}</TabsTrigger>
          <TabsTrigger class="tab" value="session">{{ t('plannedPreview.tenant.session') }}</TabsTrigger>
          <TabsTrigger class="tab" value="languages">{{ t('plannedPreview.tenant.languages') }}</TabsTrigger>
          <TabsTrigger class="tab" value="login">{{ t('plannedPreview.tenant.login') }}</TabsTrigger>
        </TabsList>
      </div>
      <TabsContent value="general" class="grid max-w-xl gap-3">
        <Field id="ts-name" :label="t('plannedPreview.tenant.friendlyName')"><input id="ts-name" disabled /></Field>
        <Field id="ts-logo" :label="t('plannedPreview.tenant.logoUrl')"><input id="ts-logo" type="url" disabled /></Field>
        <Field id="ts-email" :label="t('plannedPreview.tenant.supportEmail')"><input id="ts-email" type="email" disabled /></Field>
        <Field id="ts-url" :label="t('plannedPreview.tenant.supportUrl')"><input id="ts-url" type="url" disabled /></Field>
      </TabsContent>
      <TabsContent value="session" class="grid max-w-xl gap-3">
        <Field id="ts-idle" :label="t('plannedPreview.tenant.idleTimeout')" :hint="t('plannedPreview.tenant.idleTimeoutHint')">
          <input id="ts-idle" type="number" aria-describedby="ts-idle-hint" disabled />
        </Field>
        <Field id="ts-life" :label="t('plannedPreview.tenant.sessionLifetime')" :hint="t('plannedPreview.tenant.sessionLifetimeHint')">
          <input id="ts-life" type="number" aria-describedby="ts-life-hint" disabled />
        </Field>
      </TabsContent>
      <TabsContent value="languages" class="grid max-w-xl gap-3">
        <Field id="ts-locales" :label="t('plannedPreview.tenant.enabledLocales')">
          <select id="ts-locales" multiple disabled><option v-for="l in locales" :key="l.code">{{ l.name }}</option></select>
        </Field>
        <Field id="ts-default-locale" :label="t('plannedPreview.tenant.defaultLocale')">
          <select id="ts-default-locale" disabled><option v-for="l in locales" :key="l.code">{{ l.name }}</option></select>
        </Field>
      </TabsContent>
      <TabsContent value="login" class="grid max-w-xl gap-3">
        <Field id="ts-route" :label="t('plannedPreview.tenant.defaultRedirection')" :hint="t('plannedPreview.tenant.defaultRedirectionHint')">
          <input id="ts-route" type="url" aria-describedby="ts-route-hint" disabled />
        </Field>
      </TabsContent>
    </TabsRoot>
  </PlannedPage>
</template>
