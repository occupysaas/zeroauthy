<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Action, ActionDependency, ActionSecretInput } from '../../api/client'
import { errorMessage } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import ScriptEditor from '../connections/social/ScriptEditor.vue'
import ActionNav from './ActionNav.vue'
import { buildStatusKey, exactVersion, packageName, pendingBuild, useActionContext } from './context'
const { t } = useI18n(), { api, tenant, key, capture, current } = useActionContext()
const action = ref<Action>(), name = ref(''), code = ref(''), dependencies = ref<ActionDependency[]>([]), secrets = ref<ActionSecretInput[]>([])
const loading = ref(false), busy = ref(false), error = ref(''), notice = ref(''), reloadRequired = ref(false), baseline = ref('')
let poll: ReturnType<typeof setTimeout> | undefined, readSeq = 0
const draft = () => JSON.stringify({ name: name.value, code: code.value, dependencies: dependencies.value, secrets: secrets.value })
const dirty = computed(() => draft() !== baseline.value)
function stopPolling() { clearTimeout(poll); poll = undefined }
function apply(a: Action) {
  action.value = a; name.value = a.name; code.value = a.code
  dependencies.value = a.dependencies.map(d => ({ ...d }))
  secrets.value = a.secrets.map(s => ({ name: s.name }))
  baseline.value = draft()
}
function schedule(c: ReturnType<typeof capture>) {
  stopPolling()
  if (current(c) && pendingBuild(action.value?.status)) poll = setTimeout(() => { void read(true) }, 1500)
}
async function read(preserve = false) {
  const c = capture(), seq = ++readSeq
  if (!c) return
  if (!preserve) loading.value = true
  error.value = ''
  try {
    const a = await api.getAction(c.tenant, c.id)
    if (!current(c) || seq !== readSeq) return
    if (preserve) action.value = a
    else apply(a)
    reloadRequired.value = false
    schedule(c)
  } catch (e) { if (current(c) && seq === readSeq) error.value = errorMessage(e) }
  finally { if (current(c) && seq === readSeq) loading.value = false }
}
watch(key, () => {
  stopPolling(); ++readSeq; action.value = undefined; name.value = ''; code.value = ''; dependencies.value = []; secrets.value = []; baseline.value = ''; busy.value = false; loading.value = false; reloadRequired.value = false; error.value = ''; notice.value = ''
  void read()
}, { immediate: true })
onBeforeUnmount(stopPolling)
function validate(): boolean {
  if (!name.value || [...name.value].length > 128 || new TextEncoder().encode(code.value).length > 100000) { error.value = t('actions.invalidDraft'); return false }
  const seen = new Set<string>()
  for (const d of dependencies.value) {
    if (d.name.length > 214 || !packageName.test(d.name) || seen.has(d.name) || (d.version && d.version !== 'latest' && !exactVersion.test(d.version))) { error.value = t('actions.invalidDependency'); return false }
    seen.add(d.name)
  }
  const names = new Set<string>()
  for (const s of secrets.value) {
    if (!/^[A-Za-z0-9_]{1,128}$/.test(s.name) || names.has(s.name) || (s.value !== undefined && new TextEncoder().encode(s.value).length > 4096)) { error.value = t('actions.invalidSecret'); return false }
    names.add(s.name)
  }
  return true
}
async function save() {
  const c = capture()
  if (!c || !action.value || busy.value || reloadRequired.value || !validate()) return
  stopPolling(); ++readSeq; busy.value = true; notice.value = ''; error.value = ''
  try {
    const a = await api.updateAction(c.tenant, c.id, { runtime: 'node22', name: name.value, code: code.value, dependencies: dependencies.value.map(d => ({ ...d })), secrets: secrets.value.map(s => ({ ...s })) })
    if (!current(c)) return
    apply(a); notice.value = t('actions.saved'); schedule(c)
  } catch (e) {
    if (current(c)) { error.value = errorMessage(e); reloadRequired.value = true }
  } finally { if (current(c)) busy.value = false }
}
async function reload() {
  if (busy.value) return
  busy.value = true
  const c = capture()
  await read(true)
  if (current(c)) busy.value = false
}
async function deploy() {
  const c = capture()
  if (!c || !action.value || busy.value || dirty.value || reloadRequired.value || action.value.status !== 'built') return
  busy.value = true; error.value = ''; notice.value = ''; stopPolling(); ++readSeq
  try {
    const v = await api.deployAction(c.tenant, c.id)
    if (current(c)) { action.value = { ...action.value!, deployed_version: v, all_changes_deployed: true }; notice.value = t('actions.deployed') }
  } catch (e) { if (current(c)) { error.value = errorMessage(e); reloadRequired.value = true } }
  finally { if (current(c)) busy.value = false }
}
</script>
<template>
  <div v-if="tenant" class="stack">
    <ActionNav /><h1>{{ t('actions.editor') }}</h1>
    <Banner v-if="error" kind="error">{{ error }}</Banner><Banner v-if="notice">{{ notice }}</Banner>
    <p v-if="loading" role="status">{{ t('loading') }}</p>
    <template v-if="action">
      <section class="card stack" :aria-label="t('actions.buildStatus')">
        <div class="row"><strong>{{ action.name }}</strong><span class="flex-1" /><span role="status">{{ t(buildStatusKey(action.status)) }}</span></div>
        <p class="muted">{{ action.supported_triggers[0]?.id }} · {{ action.runtime }} <span v-if="action.deployed_version">· {{ t('actions.versionNumber', { number: action.deployed_version.number }) }}</span></p>
        <ul v-if="action.errors?.length" role="alert"><li v-for="(message, i) in action.errors" :key="i">{{ message }}</li></ul>
        <Button :disabled="busy || reloadRequired || dirty || action.status !== 'built'" @click="deploy">{{ t('actions.deploy') }}</Button>
        <p class="muted">{{ t('actions.deployHint') }}</p>
      </section>
      <form class="stack" @submit.prevent="save">
        <fieldset :disabled="busy" class="stack border-0 p-0">
          <Field id="action-name" :label="t('actions.name')"><input id="action-name" v-model="name" required maxlength="128" /></Field>
          <ScriptEditor :max-bytes="100000" id="action-code" v-model="code" :label="t('actions.code')" :readonly="busy" :hint="t('actions.codeHint')" />
          <section class="card stack" :aria-label="t('actions.dependencies')">
            <h2>{{ t('actions.dependencies') }}</h2><p id="dependency-hint" class="muted">{{ t('actions.dependencyHint') }}</p>
            <div v-for="(d, i) in dependencies" :key="i" class="row flex-wrap">
              <Field :id="'dependency-name-' + i" :label="t('actions.packageName')"><input :id="'dependency-name-' + i" v-model="d.name" aria-describedby="dependency-hint" /></Field>
              <Field :id="'dependency-version-' + i" :label="t('actions.version')"><input :id="'dependency-version-' + i" v-model="d.version" aria-describedby="dependency-hint" /></Field>
              <Button @click="dependencies.splice(i, 1)">{{ t('actions.removeDependency') }}</Button>
            </div>
            <Button :disabled="dependencies.length >= 50" @click="dependencies.push({ name: '', version: '' })">{{ t('actions.addDependency') }}</Button>
          </section>
          <section class="card stack" :aria-label="t('actions.secrets')">
            <h2>{{ t('actions.secrets') }}</h2><p id="secrets-hint" class="muted">{{ t('actions.secretHint') }}</p>
            <div v-for="(s, i) in secrets" :key="i" class="row flex-wrap">
              <Field :id="'secret-name-' + i" :label="t('actions.secretName')"><input :id="'secret-name-' + i" v-model="s.name" aria-describedby="secrets-hint" /></Field>
              <Field :id="'secret-value-' + i" :label="t('actions.secretValue')"><input :id="'secret-value-' + i" :value="s.value ?? ''" type="password" autocomplete="new-password" aria-describedby="secrets-hint" @input="s.value = ($event.target as HTMLInputElement).value" /></Field>
              <Button @click="secrets.splice(i, 1)">{{ t('actions.removeSecret') }}</Button>
            </div>
            <Button :disabled="secrets.length >= 64" @click="secrets.push({ name: '', value: '' })">{{ t('actions.addSecret') }}</Button>
          </section>
        </fieldset>
        <div class="row"><Button type="submit" variant="primary" :disabled="busy || reloadRequired">{{ t('actions.save') }}</Button><Button v-if="reloadRequired" :disabled="busy" @click="reload">{{ t('actions.reload') }}</Button></div>
        <p v-if="reloadRequired" class="muted">{{ t('actions.reloadHint') }}</p>
      </form>
    </template>
    <Button v-else-if="error" @click="read()">{{ t('retry') }}</Button>
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
