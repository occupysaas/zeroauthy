<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Action } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import { useMfaScope } from '../security/scope'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import ConfirmDialog from '../../ui/ConfirmDialog.vue'
import { providers, providerResource, resourceId, tryPhone, type PhoneProvider, type ProviderWrite } from './phone'
const { t } = useI18n(),
  { api } = useServices(),
  tenant = useTenant()
const { key, capture, current } = useMfaScope(() => tenant.value)
const provider = ref<PhoneProvider>(),
  name = ref<PhoneProvider['name']>('twilio'),
  disabled = ref(false)
const config = reactive<Record<string, string>>({}),
  credentials = reactive<Record<string, string>>({})
const text = ref(true),
  voice = ref(false),
  actions = ref<Action[]>([]),
  action = ref(''),
  to = ref(''),
  delivery = ref<'text' | 'voice'>('text')
const busy = ref(false),
  loading = ref(true),
  failed = ref(false),
  error = ref(''),
  notice = ref(''),
  confirm = ref(false)
const fields = computed(() =>
  name.value === 'twilio'
    ? ['sid', 'default_from', 'mssid']
    : name.value === 'sns'
      ? ['region', 'sender_id', 'sms_type']
      : []
)
const secrets = computed(() =>
  name.value === 'twilio' ? ['auth_token'] : name.value === 'sns' ? ['access_key_id', 'secret_access_key'] : []
)
function clearSecrets() {
  for (const k of Object.keys(credentials)) delete credentials[k]
}
function apply(p?: PhoneProvider) {
  provider.value = p ? { id: p.id, name: p.name, disabled: p.disabled, configuration: p.configuration } : undefined
  const allowed = p?.configuration?.delivery_methods ?? ['text']
  if (!allowed.includes(delivery.value)) delivery.value = allowed[0] ?? 'text'
  name.value = p?.name ?? 'twilio'
  disabled.value = p?.disabled ?? false
  for (const k of Object.keys(config)) delete config[k]
  for (const [k, v] of Object.entries(p?.configuration ?? {})) if (typeof v === 'string') config[k] = v
  text.value = p?.configuration?.delivery_methods.includes('text') ?? true
  voice.value = p?.configuration?.delivery_methods.includes('voice') ?? false
  clearSecrets()
}
watch(name, () => {
  clearSecrets()
  if (name.value === 'sns') voice.value = false
})
async function load() {
  const c = capture()
  apply()
  actions.value = []
  action.value = ''
  error.value = ''
  notice.value = ''
  busy.value = false
  loading.value = true
  failed.value = false
  if (!c) {
    loading.value = false
    return
  }
  try {
    const ps = await providers(api, c.tenant)
    if (!current(c)) return
    apply(ps[0])
    await loadActions(c)
  } catch (e) {
    if (current(c)) {
      error.value = errorMessage(e)
      failed.value = true
    }
  } finally {
    if (current(c)) loading.value = false
  }
}
async function loadActions(c: ReturnType<typeof capture>) {
  if (!c) return
  const [as, bs] = await Promise.all([
    api.allActions(c.tenant, 'custom-phone-provider'),
    api.allActionBindings(c.tenant, 'custom-phone-provider'),
  ])
  if (current(c)) {
    actions.value = as.filter((a) => !!a.deployed_version)
    action.value = bs[0]?.action?.id ?? ''
  }
}
watch(key, load, { immediate: true, flush: 'sync' })
async function save() {
  const c = capture()
  if (!c || busy.value || failed.value) return
  busy.value = true
  error.value = ''
  notice.value = ''
  const entered = Object.fromEntries(Object.entries(credentials).filter(([, v]) => v.trim()))
  clearSecrets()
  try {
    const configuration: NonNullable<ProviderWrite['configuration']> = {
      delivery_methods: [
        ...(text.value ? ['text' as const] : []),
        ...(voice.value && name.value !== 'sns' ? ['voice' as const] : []),
      ],
    }
    for (const f of fields.value) if (config[f]) Object.assign(configuration, { [f]: config[f] })
    if (name.value === 'custom') {
      if (!action.value) throw new Error(t('phone.chooseAction'))
      const selected = actions.value.find((a) => a.id === action.value)
      await api.updateActionBindings(c.tenant, 'custom-phone-provider', [
        { ref: { type: 'action_id', value: action.value }, display_name: selected?.name ?? action.value },
      ])
      if (!current(c)) return
    }
    const body: Partial<ProviderWrite> = { name: name.value, disabled: disabled.value, configuration }
    if (Object.keys(entered).length || !provider.value || provider.value.name !== name.value) body.credentials = entered
    const result = await api.writeBrandingResource<PhoneProvider>(
      c.tenant,
      provider.value?.id ? 'PATCH' : 'POST',
      provider.value?.id ? resourceId(providerResource, provider.value.id) : providerResource,
      body
    )
    if (current(c)) {
      apply(result)
      notice.value = t('saved')
    }
  } catch (e) {
    if (current(c)) error.value = errorMessage(e)
  } finally {
    for (const k of Object.keys(entered)) delete entered[k]
    if (current(c)) busy.value = false
  }
}
async function remove() {
  const c = capture()
  if (!c || !provider.value?.id || busy.value) return
  busy.value = true
  try {
    await api.writeBrandingResource(c.tenant, 'DELETE', resourceId(providerResource, provider.value.id))
    if (current(c)) {
      apply()
      confirm.value = false
    }
  } catch (e) {
    if (current(c)) error.value = errorMessage(e)
  } finally {
    if (current(c)) busy.value = false
  }
}
async function send() {
  const c = capture()
  if (!c || !provider.value?.id || busy.value) return
  busy.value = true
  error.value = ''
  notice.value = ''
  try {
    await tryPhone(api, c.tenant, resourceId(providerResource, provider.value.id), to.value, delivery.value)
    if (current(c)) notice.value = t('phone.accepted')
  } catch (e) {
    if (current(c)) error.value = errorMessage(e)
  } finally {
    if (current(c)) busy.value = false
  }
}
</script>
<template>
  <section v-if="tenant" class="stack max-w-3xl">
    <h1>{{ t('phone.providers') }}</h1>
    <Banner v-if="tenant.seeded" kind="warn">{{ t('seededBanner') }}</Banner>
    <Banner v-if="error" kind="error"
      >{{ error }} <Button v-if="failed" @click="load">{{ t('retry') }}</Button></Banner
    >
    <p v-if="loading" role="status">{{ t('loading') }}</p>
    <fieldset v-else :disabled="busy || failed" class="card stack border-0">
      <Field id="phone-provider-name" :label="t('phone.provider')"
        ><select id="phone-provider-name" v-model="name">
          <option value="twilio">Twilio</option>
          <option value="sns">Amazon SNS</option>
          <option value="custom">{{ t('phone.custom') }}</option>
        </select></Field
      >
      <label><input v-model="disabled" type="checkbox" /> {{ t('phone.disabled') }}</label>
      <Field v-for="f in fields" :id="'configuration-' + f" :key="f" :label="t(`phone.fields.${f}`)"
        ><select v-if="f === 'sms_type'" :id="'configuration-' + f" v-model="config[f]">
          <option value="">{{ t('phone.default') }}</option>
          <option>Transactional</option>
          <option>Promotional</option></select
        ><input v-else :id="'configuration-' + f" v-model="config[f]" type="text"
      /></Field>
      <div class="row">
        <label><input v-model="text" type="checkbox" /> {{ t('phone.text') }}</label
        ><label><input v-model="voice" type="checkbox" :disabled="name === 'sns'" /> {{ t('phone.voice') }}</label>
      </div>
      <p class="muted">{{ t('mfa.secretHint') }}</p>
      <Field v-for="f in secrets" :id="'credential-' + f" :key="f" :label="t(`phone.fields.${f}`)"
        ><input :id="'credential-' + f" v-model="credentials[f]" type="password" autocomplete="new-password"
      /></Field>
      <Field v-if="name === 'custom'" id="phone-action" :label="t('phone.action')" :hint="t('phone.actionHint')"
        ><select id="phone-action" v-model="action">
          <option value="">{{ t('phone.chooseAction') }}</option>
          <option v-for="a in actions" :key="a.id" :value="a.id">{{ a.name }}</option>
        </select></Field
      >
      <div class="row">
        <Button id="save-phone-provider" variant="primary" @click="save">{{ t('save') }}</Button
        ><Button v-if="provider" variant="danger" @click="confirm = true">{{ t('phone.remove') }}</Button>
      </div>
    </fieldset>
    <form v-if="provider" class="card stack" @submit.prevent="send">
      <h2>{{ t('phone.tryProvider') }}</h2>
      <p class="muted">{{ t('phone.realSend') }}</p>
      <Field id="phone-test-to" :label="t('phone.to')"
        ><input id="phone-test-to" v-model="to" type="tel" required pattern="\+[1-9][0-9]{1,14}" /></Field
      ><Field id="phone-delivery" :label="t('phone.delivery')"
        ><select id="phone-delivery" v-model="delivery">
          <option v-for="m in provider.configuration?.delivery_methods" :key="m" :value="m">
            {{ t(`phone.${m}`) }}
          </option>
        </select></Field
      ><Button id="try-phone-provider" type="submit" :disabled="busy || !!provider.disabled">{{
        t('phone.send')
      }}</Button>
    </form>
    <Banner v-if="notice" role="status">{{ notice }}</Banner
    ><ConfirmDialog
      v-model:open="confirm"
      :title="t('phone.remove')"
      :description="t('phone.removeConfirm')"
      :confirm-label="t('phone.remove')"
      :busy="busy"
      :error="error"
      @confirm="remove"
    />
  </section>
</template>
