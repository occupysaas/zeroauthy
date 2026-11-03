<script setup lang="ts">
import { ref, reactive, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { Api, type Connection, type ConnectionCreate } from '../../api/client'
import { errorMessage, useServices, useTenant } from '../../context'
import { useMfaScope } from '../security/scope'
import ClientsTab from './ClientsTab.vue'
import { asRecord, optionsOf } from './options'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
const props = defineProps<{ strategy: 'email' | 'sms' }>(),
  { t } = useI18n(),
  { api } = useServices(),
  tenant = useTenant(),
  { key, capture, current } = useMfaScope(
    () => tenant.value,
    () => props.strategy
  )
const connection = ref<Connection>(),
  loading = ref(true),
  busy = ref(false),
  failed = ref(false),
  error = ref(''),
  notice = ref(''),
  consolidated = ref(false)
const form = reactive({
  length: 6,
  lifetime: 180,
  disableSignup: false,
  brute: true,
  from: '',
  subject: '',
  body: '',
  authParams: '',
  provider: 'twilio',
  sid: '',
  mssid: '',
  gateway: '',
  audience: '',
  method: '',
  subjectGateway: '',
  secretBase64: false,
  syntax: 'liquid',
  forward: false,
})
const token = ref(''),
  secret = ref(''),
  client = ref(''),
  to = ref(''),
  send = ref('code')
function apply(c?: Connection) {
  connection.value = c
  const o = c ? optionsOf(c) : {},
    totp = asRecord(o.totp),
    email = asRecord(o.email),
    gateway = asRecord(o.gateway_authentication)
  form.length = Number(totp.length ?? 6)
  form.lifetime = Number(totp.time_step ?? 180)
  form.disableSignup = o.disable_signup === true
  form.brute = o.brute_force_protection !== false
  form.from = String(props.strategy === 'email' ? (email.from ?? '') : (o.from ?? ''))
  form.subject = String(email.subject ?? '')
  form.body = String(props.strategy === 'email' ? (email.body ?? '') : (o.template ?? ''))
  form.authParams = String(o.authParams ?? '')
  form.provider = String(o.provider ?? 'twilio')
  form.sid = String(o.twilio_sid ?? '')
  form.mssid = String(o.messaging_service_sid ?? '')
  form.gateway = String(o.gateway_url ?? '')
  form.audience = String(gateway.audience ?? '')
  form.method = String(gateway.method ?? '')
  form.subjectGateway = String(gateway.subject ?? '')
  form.secretBase64 = gateway.secret_base64_encoded === true
  form.syntax = String(o.syntax ?? 'liquid')
  form.forward = o.forward_req_info === true
  token.value = ''
  secret.value = ''
}
async function load() {
  const c = capture()
  apply()
  error.value = ''
  notice.value = ''
  busy.value = false
  loading.value = true
  failed.value = false
  client.value = ''
  to.value = ''
  if (!c) {
    loading.value = false
    return
  }
  try {
    const [list, settings] = await Promise.all([
      api.listConnections(c.tenant, { page: 0, per_page: 100, strategy: props.strategy, fields: 'id,name,strategy' }),
      api.getTenantSettings(c.tenant),
    ])
    if (!current(c)) return
    consolidated.value = settings.phone_consolidated_experience === true
    const found = list.connections.find((item) => item.strategy === props.strategy)
    if (found) {
      const detail = await api.getConnection(c.tenant, found.id)
      if (current(c)) apply(detail)
    }
  } catch (e) {
    if (current(c)) {
      failed.value = true
      error.value = errorMessage(e)
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
  const enteredToken = token.value,
    enteredSecret = secret.value
  token.value = ''
  secret.value = ''
  try {
    const o: Record<string, unknown> = {
      ...(connection.value ? optionsOf(connection.value) : {}),
      totp: { length: Number(form.length), time_step: Number(form.lifetime) },
      brute_force_protection: form.brute,
      disable_signup: form.disableSignup,
    }
    if (props.strategy === 'email') {
      const email = { ...asRecord(o.email) }
      for (const k of ['from', 'subject', 'body']) delete email[k]
      o.email = email
      if (!form.authParams) delete o.authParams
      Object.assign(o, {
        email: {
          ...asRecord(o.email),
          syntax: 'liquid',
          ...(form.from ? { from: form.from } : {}),
          ...(form.subject ? { subject: form.subject } : {}),
          ...(form.body ? { body: form.body } : {}),
        },
        ...(form.authParams ? { authParams: form.authParams } : {}),
      })
    } else if (!consolidated.value) {
      for (const k of ['from', 'template']) delete o[k]
      Object.assign(o, {
        provider: form.provider,
        syntax: form.syntax,
        forward_req_info: form.forward,
        ...(form.from ? { from: form.from } : {}),
        ...(form.body ? { template: form.body } : {}),
      })
      if (form.provider === 'twilio')
        Object.assign(o, {
          twilio_sid: form.sid,
          ...(form.mssid ? { messaging_service_sid: form.mssid } : {}),
          ...(enteredToken ? { twilio_token: enteredToken } : {}),
        })
      else
        Object.assign(o, {
          gateway_url: form.gateway,
          gateway_authentication: {
            ...asRecord(o.gateway_authentication),
            audience: form.audience,
            method: form.method,
            ...(form.subjectGateway ? { subject: form.subjectGateway } : {}),
            secret_base64_encoded: form.secretBase64,
            ...(enteredSecret ? { secret: enteredSecret } : {}),
          },
        })
    }
    const result = connection.value
      ? await api.updateConnection(c.tenant, connection.value.id, { options: o })
      : await api.createConnection(c.tenant, {
          name: props.strategy,
          strategy: props.strategy,
          options: o,
        } as ConnectionCreate)
    if (current(c)) {
      apply(result)
      notice.value = t('saved')
    }
  } catch (e) {
    if (current(c)) error.value = errorMessage(e)
  } finally {
    if (current(c)) busy.value = false
  }
}
async function testSend() {
  const c = capture()
  if (!c || busy.value) return
  busy.value = true
  error.value = ''
  notice.value = ''
  try {
    await api.request(Api.tenantOrigin(c.tenant), 'POST', '/passwordless/start', {
      body: {
        client_id: client.value,
        connection: props.strategy,
        send: props.strategy === 'email' ? send.value : 'code',
        ...(props.strategy === 'email' ? { email: to.value } : { phone_number: to.value }),
      },
    })
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
    <h1>{{ t(strategy === 'email' ? 'phone.passwordlessEmail' : 'phone.passwordlessSMS') }}</h1>
    <Banner v-if="tenant.seeded" kind="warn">{{ t('seededBanner') }}</Banner
    ><Banner v-if="error" kind="error"
      >{{ error }} <Button v-if="failed" @click="load">{{ t('retry') }}</Button></Banner
    >
    <p v-if="loading" role="status">{{ t('loading') }}</p>
    <form v-else class="card stack" @submit.prevent="save">
      <fieldset class="stack border-0" :disabled="busy || failed">
        <label><input v-model="form.disableSignup" type="checkbox" /> {{ t('conns.disableSignup') }}</label
        ><label><input v-model="form.brute" type="checkbox" /> {{ t('conns.bruteForce') }}</label
        ><Field id="passwordless-length" :label="t('phone.codeLength')"
          ><input
            id="passwordless-length"
            v-model.number="form.length"
            type="number"
            min="4"
            max="40"
            required /></Field
        ><Field id="passwordless-lifetime" :label="t('phone.lifetime')"
          ><input id="passwordless-lifetime" v-model.number="form.lifetime" type="number" min="60" required
        /></Field>
        <template v-if="strategy === 'email'"
          ><Field id="passwordless-subject" :label="t('phone.subject')"
            ><input id="passwordless-subject" v-model="form.subject" /></Field
          ><Field id="passwordless-auth-params" :label="t('phone.authParams')">
            <textarea id="passwordless-auth-params" v-model="form.authParams" /></Field
        ></template>
        <Banner v-if="strategy === 'sms' && consolidated"
          >{{ t('phone.consolidated') }}
          <RouterLink :to="{ name: 'phone-providers', params: { tenant: tenant.name } }">{{
            t('phone.providers')
          }}</RouterLink></Banner
        >
        <template v-if="strategy === 'email' || !consolidated"
          ><Field id="passwordless-from" :label="t('phone.fields.default_from')"
            ><input id="passwordless-from" v-model="form.from" /></Field
          ><Field id="passwordless-body" :label="t('phone.body')">
            <textarea id="passwordless-body" v-model="form.body" rows="6" /></Field
        ></template>
        <template v-if="strategy === 'sms' && !consolidated"
          ><Field id="passwordless-provider" :label="t('phone.provider')"
            ><select id="passwordless-provider" v-model="form.provider">
              <option value="twilio">Twilio</option>
              <option value="sms_gateway">{{ t('phone.gateway') }}</option>
            </select></Field
          ><Field id="passwordless-syntax" :label="t('phone.syntax')"
            ><select id="passwordless-syntax" v-model="form.syntax">
              <option value="liquid">Liquid</option>
              <option value="md_with_macros">{{ t('phone.macros') }}</option>
            </select></Field
          ><label><input v-model="form.forward" type="checkbox" /> {{ t('phone.forward') }}</label>
          <p class="muted">{{ t('mfa.secretHint') }}</p>
          <template v-if="form.provider === 'twilio'"
            ><Field id="passwordless-sid" :label="t('phone.fields.sid')"
              ><input id="passwordless-sid" v-model="form.sid" /></Field
            ><Field id="passwordless-mssid" :label="t('phone.fields.mssid')"
              ><input id="passwordless-mssid" v-model="form.mssid" /></Field
            ><Field id="passwordless-token" :label="t('phone.fields.auth_token')"
              ><input id="passwordless-token" v-model="token" type="password" autocomplete="new-password" /></Field
          ></template>
          <template v-else
            ><Field id="passwordless-gateway" :label="t('phone.gatewayURL')"
              ><input id="passwordless-gateway" v-model="form.gateway" type="url" /></Field
            ><Field
              v-for="f in ['audience', 'method', 'subjectGateway'] as const"
              :id="'passwordless-' + f"
              :key="f"
              :label="t(`phone.${f}`)"
              ><input :id="'passwordless-' + f" v-model="form[f]" /></Field
            ><label><input v-model="form.secretBase64" type="checkbox" /> {{ t('phone.secretBase64') }}</label
            ><Field id="passwordless-secret" :label="t('phone.secret')"
              ><input
                id="passwordless-secret"
                v-model="secret"
                type="password"
                autocomplete="new-password" /></Field></template
        ></template>
        <Button id="save-passwordless" type="submit" variant="primary">{{ t('save') }}</Button>
      </fieldset>
    </form>
    <details v-if="connection" data-passwordless-applications class="card stack">
      <summary>{{ t('conns.applications') }}</summary>
      <ClientsTab :key="tenant.name + connection.id" :tenant="tenant" :connection="connection" />
    </details>
    <form v-if="connection" class="card stack" @submit.prevent="testSend">
      <h2>{{ t('phone.testConnection') }}</h2>
      <p class="muted">{{ t('phone.realSend') }} {{ t('phone.clientHint') }}</p>
      <Field id="passwordless-client" :label="t('phone.client')"
        ><input id="passwordless-client" v-model="client" required /></Field
      ><Field id="passwordless-to" :label="t('phone.to')"
        ><input id="passwordless-to" v-model="to" :type="strategy === 'email' ? 'email' : 'tel'" required /></Field
      ><Field v-if="strategy === 'email'" id="passwordless-send" :label="t('phone.sendType')"
        ><select id="passwordless-send" v-model="send">
          <option value="code">{{ t('phone.code') }}</option>
          <option value="link">{{ t('phone.link') }}</option>
        </select></Field
      ><Button id="try-passwordless" type="submit" :disabled="busy || failed">{{ t('phone.send') }}</Button>
    </form>
    <Banner v-if="notice" role="status">{{ notice }}</Banner>
  </section>
</template>
