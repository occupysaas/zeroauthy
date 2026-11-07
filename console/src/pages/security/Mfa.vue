<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { GuardianFactors, GuardianPolicies, TenantSettingsPatch } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import Field from '../../ui/Field.vue'
import Button from '../../ui/Button.vue'
import { providers } from '../branding/phone'
import MfaConfiguration from './MfaConfiguration.vue'
import { configurations } from './configuration'
import { mfaUnavailable, useMfaScope } from './scope'
const { t } = useI18n(),
  { api } = useServices(),
  tenant = useTenant()
const { key, capture, current } = useMfaScope(() => tenant.value)
const names = [
  'push-notification',
  'sms',
  'email',
  'duo',
  'otp',
  'webauthn-roaming',
  'webauthn-platform',
  'recovery-code',
] as const
const factors = ref<GuardianFactors>([]),
  policy = ref<GuardianPolicies[number] | ''>(''),
  showList = ref(false),
  customize = ref(false)
const error = ref(''),
  loading = ref(true),
  busy = ref(false),
  unavailable = ref(false)
const phoneReady = ref(false),
  voiceReady = ref(false),
  providerError = ref(''),
  messageTypes = ref<('sms' | 'voice')[]>(['sms'])
const uv = ref<'discouraged' | 'preferred' | 'required'>('discouraged')
const uvReady = ref(false)
const status = (name: string) => ['duo', 'push-notification'].includes(name) ? 'notPlanned' : 'enforced'
function fail(e: unknown) {
  unavailable.value = mfaUnavailable(e)
  error.value = unavailable.value ? t('mfa.unavailable') : errorMessage(e)
}
async function load() {
  const c = capture()
  uvReady.value = false
  uv.value = 'discouraged'
  phoneReady.value = false
  voiceReady.value = false
  providerError.value = ''
  messageTypes.value = ['sms']
  factors.value = []
  policy.value = ''
  showList.value = false
  customize.value = false
  busy.value = false
  error.value = ''
  unavailable.value = false
  if (!c) {
    loading.value = false
    return
  }
  loading.value = true
  try {
    const [f, p, settings, roaming] = await Promise.all([
      api.getGuardianFactors(c.tenant),
      api.getGuardianPolicies(c.tenant),
      api.getTenantSettings(c.tenant),
      api.getRoamingUV(c.tenant),
    ])
    if (!current(c)) return
    uv.value = roaming.user_verification ?? 'discouraged'
    uvReady.value = true
    factors.value = f
    policy.value = p[0] ?? ''
    showList.value = settings.flags?.mfa_show_factor_list_on_enrollment ?? false
    customize.value = settings.customize_mfa_in_postlogin_action ?? false
    try {
      let legacy = ''
      if (!settings.phone_consolidated_experience) {
        const selected = (await api.getGuardianConfiguration(c.tenant, 'phone/selected-provider')) as {
          provider?: string
        }
        if (!current(c)) return
        if (selected.provider) legacy = selected.provider
        else {
          const fallback = (await api.getGuardianConfiguration(c.tenant, 'sms/selected-provider')) as {
            provider?: string
          }
          if (!current(c)) return
          legacy = fallback.provider ?? 'auth0'
        }
      }
      let delivery: string[] = []
      if (legacy === 'twilio') {
        let config = (await api.getGuardianConfiguration(c.tenant, 'phone/providers/twilio')) as {
          sid?: string
          from?: string
          messaging_service_sid?: string
        }
        if (!current(c)) return
        if (!config.sid) {
          config = (await api.getGuardianConfiguration(c.tenant, 'sms/providers/twilio')) as typeof config
          if (!current(c)) return
        }
        if (config.sid && (config.from || config.messaging_service_sid)) delivery = ['text', 'voice']
      } else if (legacy === 'phone-message-hook') {
        const bindings = await api.allActionBindings(c.tenant, 'send-phone-message')
        const actions = bindings.length ? await api.allActions(c.tenant, 'send-phone-message') : []
        if (!current(c)) return
        if (
          bindings.some((binding) =>
            actions.some((action) => action.id === binding.action?.id && action.deployed_version)
          )
        )
          delivery = ['text', 'voice']
      } else {
        const ps = await providers(api, c.tenant)
        if (!current(c)) return
        let active = ps.find((p) => !p.disabled)
        if (active?.name === 'custom') {
          const bindings = await api.allActionBindings(c.tenant, 'custom-phone-provider')
          const actions = bindings.length ? await api.allActions(c.tenant, 'custom-phone-provider') : []
          if (!current(c)) return
          if (
            !bindings.some((binding) =>
              actions.some((action) => action.id === binding.action?.id && action.deployed_version)
            )
          )
            active = undefined
        }
        if (active) delivery = active.configuration?.delivery_methods ?? []
      }
      const messageConfig = await api.getGuardianConfiguration(c.tenant, 'phone/message-types')
      if (!current(c)) return
      const configured = (messageConfig as { message_types?: ('sms' | 'voice')[] }).message_types
      messageTypes.value = configured ?? ['sms']
      phoneReady.value = delivery.includes('text')
      voiceReady.value = delivery.includes('voice')
    } catch (e) {
      if (current(c)) providerError.value = errorMessage(e)
    }
  } catch (e) {
    if (current(c)) fail(e)
  } finally {
    if (current(c)) loading.value = false
  }
}
watch(key, load, { immediate: true, flush: 'sync' })
async function toggle(name: (typeof names)[number], event: Event) {
  const c = capture()
  if (!c || busy.value || (name === 'sms' && !phoneReady.value && !voiceReady.value)) return
  const input = event.target as HTMLInputElement,
    enabled = input.checked
  input.checked = factors.value.some((f) => f.name === name && f.enabled)
  busy.value = true
  error.value = ''
  try {
    const result = await api.setGuardianFactor(c.tenant, name, enabled)
    if (!current(c)) return
    factors.value = factors.value.map((f) => (f.name === name ? { ...f, enabled: result.enabled } : f))
    const refreshed = await api.getGuardianFactors(c.tenant)
    if (current(c)) factors.value = refreshed
  } catch (e) {
    if (current(c)) fail(e)
  } finally {
    if (current(c)) busy.value = false
  }
}
async function setUV(event: Event) {
  const c = capture(); if (!c || busy.value || !uvReady.value) return
  const value = (event.target as HTMLSelectElement).value as typeof uv.value
  const previous = uv.value; uv.value = value; busy.value = true; error.value = ''
  try { const result = await api.setRoamingUV(c.tenant, value); if (current(c)) uv.value = result.user_verification }
  catch (e) { if (current(c)) { uv.value = previous; fail(e) } }
  finally { if (current(c)) busy.value = false }
}
async function setMessageType(value: 'sms' | 'voice', event: Event) {
  const c = capture()
  if (!c || busy.value) return
  const input = event.target as HTMLInputElement,
    enabled = input.checked
  input.checked = messageTypes.value.includes(value)
  const previous = [...messageTypes.value]
  const next = enabled ? [...new Set([...previous, value])] : previous.filter((item) => item !== value)
  busy.value = true
  error.value = ''
  try {
    await api.setGuardianConfiguration(c.tenant, 'phone/message-types', { message_types: next })
    if (current(c)) messageTypes.value = next
  } catch (e) {
    if (current(c)) fail(e)
  } finally {
    if (current(c)) busy.value = false
  }
}
async function setPolicy(event: Event) {
  const c = capture()
  if (!c || busy.value) return
  const value = (event.target as HTMLInputElement).value as GuardianPolicies[number] | ''
  const previous = policy.value
  policy.value = value
  busy.value = true
  error.value = ''
  try {
    const result = await api.setGuardianPolicies(c.tenant, value ? [value] : [])
    if (current(c)) policy.value = result[0] ?? ''
  } catch (e) {
    if (current(c)) {
      policy.value = previous
      fail(e)
    }
  } finally {
    if (current(c)) busy.value = false
  }
}
async function setFlag(name: 'mfa_show_factor_list_on_enrollment' | 'customize_mfa_in_postlogin_action', event: Event) {
  const c = capture()
  if (!c || busy.value) return
  const enabled = (event.target as HTMLInputElement).checked
  const flag = name === 'customize_mfa_in_postlogin_action' ? customize : showList
  const previous = flag.value
  flag.value = enabled
  const body: TenantSettingsPatch =
    name === 'customize_mfa_in_postlogin_action' ? { [name]: enabled } : { flags: { [name]: enabled } }
  busy.value = true
  error.value = ''
  try {
    await api.updateTenantSettings(c.tenant, body)
  } catch (e) {
    if (current(c)) {
      flag.value = previous
      fail(e)
    }
  } finally {
    if (current(c)) busy.value = false
  }
}
</script>
<template>
  <div v-if="tenant" class="stack">
    <h1>{{ t('nav.mfa') }}</h1>
    <Banner v-if="tenant.seeded" kind="warn">{{ t('seededBanner') }}</Banner>
    <Banner v-if="error" kind="error"
      >{{ error }} <Button @click="load">{{ t('retry') }}</Button></Banner
    >
    <p v-if="loading" role="status">{{ t('loading') }}</p>
    <fieldset v-if="!loading && !unavailable" :disabled="busy" class="card stack border-0">
      <legend>{{ t('mfa.factors') }}</legend>
      <div v-for="name in names" :key="name" :data-factor="name" class="stack">
        <label :for="'factor-' + name"
          ><input
            :id="'factor-' + name"
            type="checkbox"
            :disabled="name === 'sms' && !phoneReady && !voiceReady"
            :checked="factors.some((f) => f.name === name && f.enabled)"
            @change="toggle(name, $event)"
          />
          {{ t(`mfa.factorNames.${name}`) }}</label
        >
        <p v-if="name === 'sms' && !phoneReady && !voiceReady" class="muted">
          {{ t('phone.providerRequired') }} {{ providerError }}
        </p>
        <p v-else class="muted">
          {{ t(`mfa.${status(name)}`) }}
          <span v-if="factors.some((f) => f.name === name && f.trial_expired)">{{ t('mfa.trialExpired') }}</span>
        </p>
      </div>
      <Field id="webauthn-uv" :label="t('passkeys.uv')"><select id="webauthn-uv" :value="uv" :disabled="!uvReady" @change="setUV"><option v-for="value in ['discouraged', 'preferred', 'required']" :key="value" :value="value">{{ t(`passkeys.uvValues.${value}`) }}</option></select></Field>
      <Banner v-if="factors.some(f => f.name === 'webauthn-platform' && f.requires_other_factor)" kind="warn">{{ t('passkeys.platformWarning') }}</Banner>
      <fieldset class="stack">
        <legend>{{ t('phone.delivery') }}</legend>
        <label
          ><input
            id="phone-sms"
            type="checkbox"
            :checked="messageTypes.includes('sms')"
            :disabled="!phoneReady"
            @change="setMessageType('sms', $event)"
          />
          {{ t('phone.text') }}</label
        >
        <label
          ><input
            id="phone-voice"
            type="checkbox"
            :checked="messageTypes.includes('voice')"
            :disabled="!voiceReady"
            @change="setMessageType('voice', $event)"
          />
          {{ t('phone.voice') }}</label
        >
        <Button variant="ghost" @click="load">{{ t('phone.refreshProvider') }}</Button>
        <p v-if="!phoneReady && !voiceReady" class="muted">{{ t('phone.providerRequired') }}</p>
        <p v-else-if="!voiceReady" class="muted">{{ t('phone.voiceUnavailable') }}</p>
      </fieldset>
      <fieldset class="stack">
        <legend>{{ t('mfa.policy') }}</legend>
        <label
          v-for="p in [
            { value: '', label: 'never' },
            { value: 'all-applications', label: 'always' },
            { value: 'confidence-score', label: 'adaptive' },
          ]"
          :key="p.value"
          ><input type="radio" name="mfa-policy" :value="p.value" :checked="policy === p.value" @change="setPolicy" />
          {{ t(`mfa.${p.label}`) }}</label
        >
        <p class="muted">{{ t('mfa.adaptiveNote') }}</p>
      </fieldset>
      <label for="mfa_show_factor_list_on_enrollment"
        ><input
          id="mfa_show_factor_list_on_enrollment"
          type="checkbox"
          :checked="showList"
          @change="setFlag('mfa_show_factor_list_on_enrollment', $event)"
        />
        {{ t('mfa.showList') }}</label
      >
      <label for="customize_mfa_in_postlogin_action"
        ><input
          id="customize_mfa_in_postlogin_action"
          type="checkbox"
          :checked="customize"
          @change="setFlag('customize_mfa_in_postlogin_action', $event)"
        />
        {{ t('mfa.customize') }}</label
      >
    </fieldset>
    <details v-if="!loading && !unavailable" class="stack">
      <summary>{{ t('phone.mfaSettings') }}</summary>
      <MfaConfiguration
        v-for="config in configurations.filter((item) => item.route !== 'phone/message-types')"
        :key="config.route"
        :tenant="tenant"
        :config="config"
      />
    </details>
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
