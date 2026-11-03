<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { errorMessage, useServices, useTenant } from '../../context'
import { useMfaScope } from '../security/scope'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import { templateResource, resourceId, tryPhone, type PhoneTemplate } from './phone'
const { t } = useI18n(),
  { api } = useServices(),
  tenant = useTenant(),
  { key, capture, current } = useMfaScope(() => tenant.value)
const types = ['otp_verify', 'otp_enroll', 'change_password', 'blocked_account', 'password_breach'] as const
const templates = ref<PhoneTemplate[]>([]),
  type = ref<PhoneTemplate['type']>('otp_verify'),
  text = ref(''),
  voice = ref(''),
  from = ref(''),
  disabled = ref(false),
  to = ref(''),
  delivery = ref<'text' | 'voice'>('text')
const loading = ref(true),
  busy = ref(false),
  failed = ref(false),
  error = ref(''),
  notice = ref('')
const selected = computed(() => templates.value.find((item) => item.type === type.value))
const draft = computed(() =>
    JSON.stringify({ text: text.value, voice: voice.value, from: from.value, disabled: disabled.value })
  ),
  savedDraft = ref('')
const preview = computed(() =>
  (delivery.value === 'voice' ? voice.value : text.value).replace(
    /{{\s*(code|application.name|tenant.friendly_name)\s*}}/g,
    (_, key: string) => (key === 'code' ? '123456' : 'Example application')
  )
)
function apply() {
  text.value = selected.value?.content.body?.text ?? ''
  voice.value = selected.value?.content.body?.voice ?? ''
  from.value = selected.value?.content.from ?? ''
  disabled.value = selected.value?.disabled ?? false
  savedDraft.value = draft.value
  notice.value = ''
}
watch(type, apply)
async function load() {
  const c = capture()
  templates.value = []
  apply()
  error.value = ''
  notice.value = ''
  failed.value = false
  busy.value = false
  loading.value = true
  if (!c) {
    loading.value = false
    return
  }
  try {
    const result = await api.getBrandingResource<{ templates: PhoneTemplate[] }>(c.tenant, templateResource)
    if (current(c)) {
      templates.value = result.templates ?? []
      apply()
    }
  } catch (e) {
    if (current(c)) {
      error.value = errorMessage(e)
      failed.value = true
    }
  } finally {
    if (current(c)) loading.value = false
  }
}
watch(key, load, { immediate: true, flush: 'sync' })
async function save() {
  const c = capture()
  if (!c || busy.value || failed.value) return
  busy.value = true
  error.value = ''
  notice.value = ''
  const chosen = type.value,
    existing = selected.value
  try {
    const content = {
      ...(from.value ? { from: from.value } : {}),
      body: { ...(text.value ? { text: text.value } : {}), ...(voice.value ? { voice: voice.value } : {}) },
    }
    const result = await api.writeBrandingResource<PhoneTemplate>(
      c.tenant,
      existing?.id ? 'PATCH' : 'POST',
      existing?.id ? resourceId(templateResource, existing.id) : templateResource,
      { ...(existing ? {} : { type: chosen }), content, disabled: disabled.value }
    )
    if (current(c) && type.value === chosen) {
      templates.value = templates.value
        .filter((item) => item.type !== chosen)
        .concat(
          result?.type ? result : { ...existing, id: existing?.id, type: chosen, content, disabled: disabled.value }
        )
      apply()
      notice.value = t('saved')
    }
  } catch (e) {
    if (current(c)) error.value = errorMessage(e)
  } finally {
    if (current(c)) busy.value = false
  }
}
async function reset() {
  const c = capture(),
    id = selected.value?.id,
    chosen = type.value
  if (!c || !id || busy.value) return
  busy.value = true
  error.value = ''
  try {
    const result = await api.writeBrandingResource<PhoneTemplate>(
      c.tenant,
      'POST',
      resourceId(templateResource, id) + '/reset'
    )
    if (current(c) && type.value === chosen) {
      templates.value = templates.value.filter((item) => item.type !== chosen).concat(result)
      apply()
    }
  } catch (e) {
    if (current(c)) error.value = errorMessage(e)
  } finally {
    if (current(c)) busy.value = false
  }
}
async function send() {
  const c = capture(),
    id = selected.value?.id
  if (!c || !id || busy.value || draft.value !== savedDraft.value) return
  busy.value = true
  error.value = ''
  notice.value = ''
  try {
    await tryPhone(api, c.tenant, resourceId(templateResource, id), to.value, delivery.value)
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
    <h1>{{ t('phone.templates') }}</h1>
    <Banner v-if="tenant.seeded" kind="warn">{{ t('seededBanner') }}</Banner
    ><Banner v-if="error" kind="error"
      >{{ error }} <Button v-if="failed" @click="load">{{ t('retry') }}</Button></Banner
    >
    <p v-if="loading" role="status">{{ t('loading') }}</p>
    <fieldset v-else class="card stack border-0" :disabled="busy || failed">
      <Field id="phone-template-type" :label="t('phone.templateType')"
        ><select id="phone-template-type" v-model="type">
          <option v-for="item in types" :key="item" :value="item">{{ t(`phone.templateTypes.${item}`) }}</option>
        </select></Field
      ><label><input v-model="disabled" type="checkbox" /> {{ t('phone.disabled') }}</label
      ><Field id="phone-template-from" :label="t('phone.fields.default_from')"
        ><input id="phone-template-from" v-model="from" type="tel" /></Field
      ><Field id="phone-template-text" :label="t('phone.text')">
        <textarea id="phone-template-text" v-model="text" rows="5" /></Field
      ><Field id="phone-template-voice" :label="t('phone.voice')">
        <textarea id="phone-template-voice" v-model="voice" rows="5" />
      </Field>
      <div class="row">
        <Button id="save-phone-template" @click="save">{{ t('save') }}</Button
        ><Button v-if="selected?.id" @click="reset">{{ t('phone.reset') }}</Button>
      </div>
    </fieldset>
    <section class="card stack">
      <h2>{{ t('phone.preview') }}</h2>
      <p class="muted">{{ t('phone.previewHint') }}</p>
      <pre data-phone-preview class="whitespace-pre-wrap">{{ preview }}</pre>
    </section>
    <form v-if="selected?.id" class="card stack" @submit.prevent="send">
      <h2>{{ t('phone.tryTemplate') }}</h2>
      <p class="muted">{{ t('phone.realSend') }} {{ t('phone.saveBeforeTry') }}</p>
      <Field id="phone-template-to" :label="t('phone.to')"
        ><input id="phone-template-to" v-model="to" type="tel" required pattern="\+[1-9][0-9]{1,14}" /></Field
      ><Field id="phone-template-delivery" :label="t('phone.delivery')"
        ><select id="phone-template-delivery" v-model="delivery">
          <option value="text">{{ t('phone.text') }}</option>
          <option value="voice">{{ t('phone.voice') }}</option>
        </select></Field
      ><Button id="try-phone-template" type="submit" :disabled="busy || disabled || draft !== savedDraft">{{
        t('phone.send')
      }}</Button>
    </form>
    <Banner v-if="notice" role="status">{{ notice }}</Banner>
  </section>
</template>
