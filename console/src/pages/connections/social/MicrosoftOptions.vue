<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import Banner from '../../../ui/Banner.vue'
import Field from '../../../ui/Field.vue'

withDefaults(defineProps<{ strategy: string; readonly?: boolean; error?: string }>(), { readonly: false, error: '' })
const mode = defineModel<string>('mode', { default: 'single' })
const tenantDomain = defineModel<string>('tenantDomain', { default: '' })
const { t } = useI18n()
</script>

<template>
  <section class="stack" :aria-label="t(`social.strategies.${strategy}`)">
    <p class="muted">{{ t('social.microsoftV2') }}</p>
    <p class="muted">{{ t('social.microsoftScopes') }}</p>
    <p class="muted">{{ t('social.microsoftEmail') }}</p>
    <template v-if="strategy === 'waad'">
      <Field id="microsoft-mode" :label="t('social.microsoftMode')" :hint="readonly ? t('social.microsoftBindingFixed') : t('social.microsoftModeHint')">
        <input v-if="readonly" id="microsoft-mode" :value="t(mode === 'organizations' ? 'social.microsoftOrganizations' : 'social.microsoftSingle')" type="text" readonly aria-describedby="microsoft-mode-hint" />
        <select v-else id="microsoft-mode" v-model="mode" aria-describedby="microsoft-mode-hint">
          <option value="single">{{ t('social.microsoftSingle') }}</option>
          <option value="organizations">{{ t('social.microsoftOrganizations') }}</option>
        </select>
      </Field>
      <Banner v-if="mode === 'organizations'" kind="warn" data-testid="any-organization-warning">{{ t('social.microsoftAnyWarning') }}</Banner>
      <Field v-else id="microsoft-tenant" :label="t('social.microsoftTenant')" :hint="readonly ? t('social.microsoftBindingFixed') : t('social.microsoftTenantHint')" :error="error">
        <input id="microsoft-tenant" v-model="tenantDomain" type="text" :readonly="readonly" autocomplete="off" spellcheck="false" :aria-invalid="!!error" :aria-describedby="error ? 'microsoft-tenant-hint microsoft-tenant-error' : 'microsoft-tenant-hint'" />
      </Field>
    </template>
  </section>
</template>
