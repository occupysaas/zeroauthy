<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { GuardianFactors, GuardianPolicies, TenantSettingsPatch } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import MfaConfiguration from './MfaConfiguration.vue'
import { configurations } from './configuration'
import { mfaUnavailable, useMfaScope } from './scope'
const { t } = useI18n(), { api } = useServices(), tenant = useTenant()
const { key, capture, current } = useMfaScope(() => tenant.value)
const names = ['push-notification', 'sms', 'email', 'duo', 'otp', 'webauthn-roaming', 'webauthn-platform', 'recovery-code'] as const
const factors = ref<GuardianFactors>([]), policy = ref<GuardianPolicies[number] | ''>(''), showList = ref(false), customize = ref(false)
const error = ref(''), loading = ref(true), busy = ref(false), unavailable = ref(false)
const status = (name: string) => name.startsWith('webauthn-') ? 'stored33b' : name === 'sms' ? 'stored34' : ['duo', 'push-notification'].includes(name) ? 'notPlanned' : 'enforced'
function fail(e: unknown) { unavailable.value = mfaUnavailable(e); error.value = unavailable.value ? t('mfa.unavailable') : errorMessage(e) }
async function load() {
  const c = capture(); factors.value = []; policy.value = ''; showList.value = false; customize.value = false; busy.value = false; error.value = ''; unavailable.value = false
  if(!c) { loading.value = false; return }
  loading.value = true
  try {
    const [f, p, settings] = await Promise.all([api.getGuardianFactors(c.tenant), api.getGuardianPolicies(c.tenant), api.getTenantSettings(c.tenant)])
    if(!current(c)) return
    factors.value = f; policy.value = p[0] ?? ''; showList.value = settings.flags?.mfa_show_factor_list_on_enrollment ?? false; customize.value = settings.customize_mfa_in_postlogin_action ?? false
  } catch(e) { if(current(c)) fail(e) }
  finally { if(current(c)) loading.value = false }
}
watch(key, load, { immediate: true, flush: 'sync' })
async function toggle(name: typeof names[number], event: Event) {
  const c = capture(); if(!c || busy.value) return
  const input = event.target as HTMLInputElement, enabled = input.checked
  input.checked = factors.value.some(f => f.name === name && f.enabled)
  busy.value = true; error.value = ''
  try {
    const result = await api.setGuardianFactor(c.tenant, name, enabled)
    if(current(c)) factors.value = factors.value.map(f => f.name === name ? { ...f, enabled: result.enabled } : f)
  } catch(e) { if(current(c)) fail(e) }
  finally { if(current(c)) busy.value = false }
}
async function setPolicy(event: Event) {
  const c = capture(); if(!c || busy.value) return
  const value = (event.target as HTMLInputElement).value as GuardianPolicies[number] | ''
  const previous = policy.value
  policy.value = value; busy.value = true; error.value = ''
  try { const result = await api.setGuardianPolicies(c.tenant, value ? [value] : []); if(current(c)) policy.value = result[0] ?? '' }
  catch(e) { if(current(c)) { policy.value = previous; fail(e) } }
  finally { if(current(c)) busy.value = false }
}
async function setFlag(name: 'mfa_show_factor_list_on_enrollment' | 'customize_mfa_in_postlogin_action', event: Event) {
  const c = capture(); if(!c || busy.value) return
  const enabled = (event.target as HTMLInputElement).checked
  const flag = name === 'customize_mfa_in_postlogin_action' ? customize : showList
  const previous = flag.value; flag.value = enabled
  const body: TenantSettingsPatch = name === 'customize_mfa_in_postlogin_action' ? { [name]: enabled } : { flags: { [name]: enabled } }
  busy.value = true; error.value = ''
  try { await api.updateTenantSettings(c.tenant, body) }
  catch(e) { if(current(c)) { flag.value = previous; fail(e) } }
  finally { if(current(c)) busy.value = false }
}
</script>
<template>
  <div v-if="tenant" class="stack">
    <h1>{{ t('nav.mfa') }}</h1>
    <Banner v-if="tenant.seeded" kind="warn">{{ t('seededBanner') }}</Banner>
    <Banner v-if="error" kind="error">{{ error }} <Button @click="load">{{ t('retry') }}</Button></Banner>
    <p v-if="loading" role="status">{{ t('loading') }}</p>
    <fieldset v-if="!loading && !unavailable" :disabled="busy" class="card stack border-0">
      <legend>{{ t('mfa.factors') }}</legend>
      <div v-for="name in names" :key="name" :data-factor="name" class="stack">
        <label :for="'factor-' + name"><input :id="'factor-' + name" type="checkbox" :checked="factors.some(f => f.name === name && f.enabled)" @change="toggle(name, $event)" /> {{ t(`mfa.factorNames.${name}`) }}</label>
        <p class="muted">{{ t(`mfa.${status(name)}`) }} <span v-if="factors.some(f => f.name === name && f.trial_expired)">{{ t('mfa.trialExpired') }}</span></p>
      </div>
      <fieldset class="stack"><legend>{{ t('mfa.policy') }}</legend>
        <label v-for="p in [{ value: '', label: 'never' }, { value: 'all-applications', label: 'always' }, { value: 'confidence-score', label: 'adaptive' }]" :key="p.value"><input type="radio" name="mfa-policy" :value="p.value" :checked="policy === p.value" @change="setPolicy" /> {{ t(`mfa.${p.label}`) }}</label>
        <p class="muted">{{ t('mfa.adaptiveNote') }}</p>
      </fieldset>
      <label for="mfa_show_factor_list_on_enrollment"><input id="mfa_show_factor_list_on_enrollment" type="checkbox" :checked="showList" @change="setFlag('mfa_show_factor_list_on_enrollment', $event)" /> {{ t('mfa.showList') }}</label>
      <label for="customize_mfa_in_postlogin_action"><input id="customize_mfa_in_postlogin_action" type="checkbox" :checked="customize" @change="setFlag('customize_mfa_in_postlogin_action', $event)" /> {{ t('mfa.customize') }}</label>
    </fieldset>
    <details v-if="!loading && !unavailable" class="stack"><summary>{{ t('mfa.storedSettings') }}</summary><MfaConfiguration v-for="config in configurations" :key="config.route" :tenant="tenant" :config="config" /></details>
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
