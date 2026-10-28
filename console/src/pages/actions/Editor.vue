<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { ActionModule, ActionModuleRef, ActionModuleVersion, Action, ActionDependency, ActionSecretInput } from '../../api/client'
import { errorMessage } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import ScriptEditor from '../connections/social/ScriptEditor.vue'
import ActionNav from './ActionNav.vue'
import { buildStatusKey, exactVersion, packageName, pendingBuild, useActionContext } from './context'
const { t } = useI18n(), { api, tenant, key, capture, current } = useActionContext()
const action = ref<Action>(), name = ref(''), code = ref(''), dependencies = ref<ActionDependency[]>([]), secrets = ref<ActionSecretInput[]>([])
const modules = ref<ActionModuleRef[]>([]), availableModules = ref<ActionModule[]>([]), moduleVersions = ref<Record<string, ActionModuleVersion[]>>({}), moduleChoice = ref(''), versionChoice = ref('')
let moduleReads = 0
const loading = ref(false), busy = ref(false), error = ref(''), notice = ref(''), reloadRequired = ref(false), baseline = ref('')
let poll: ReturnType<typeof setTimeout> | undefined, readSeq = 0
const draft = () => JSON.stringify({ name: name.value, code: code.value, dependencies: dependencies.value, secrets: secrets.value, modules: modules.value })
const dirty = computed(() => draft() !== baseline.value)
function stopPolling() { clearTimeout(poll); poll = undefined }
function apply(a: Action) {
  action.value = a; name.value = a.name; code.value = a.code
  dependencies.value = a.dependencies.map(d => ({ ...d }))
  secrets.value = a.secrets.map(s => ({ name: s.name }))
  modules.value = (a.modules ?? []).map(m => ({ ...m }))
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
  stopPolling(); ++readSeq; ++moduleReads; modules.value = []; availableModules.value = []; moduleVersions.value = {}; moduleChoice.value = ''; versionChoice.value = ''; action.value = undefined; name.value = ''; code.value = ''; dependencies.value = []; secrets.value = []; baseline.value = ''; busy.value = false; loading.value = false; reloadRequired.value = false; error.value = ''; notice.value = ''
  void read(); void loadModules()
}, { immediate: true })
onBeforeUnmount(stopPolling)
async function loadModules() {
 const c = capture(); if(!c) return
 try { const all: ActionModule[] = []; for(let page = 0; ; page++) { const r = await api.listActionModules(c.tenant, { page, per_page: 100 }); if(!current(c)) return; all.push(...r.modules); if(all.length >= r.total || !r.modules.length) break }; availableModules.value = all }
 catch(e) { if(current(c)) error.value = errorMessage(e) }
}
watch(moduleChoice, async id => {
 const c = capture(), seq = ++moduleReads; versionChoice.value = ''; if(!c || !id) return
 try { const versions: ActionModuleVersion[] = []; for(let page = 0; ; page++) { const r = await api.listActionModuleVersions(c.tenant, id, { page, per_page: 100 }); if(!current(c) || seq !== moduleReads) return; versions.push(...r.versions); if(versions.length >= r.total || !r.versions.length) break }; moduleVersions.value[id] = versions }
 catch(e) { if(current(c) && seq === moduleReads) error.value = errorMessage(e) }
})
function addModule() {
 const m = availableModules.value.find(m => m.id === moduleChoice.value), v = moduleVersions.value[moduleChoice.value]?.find(v => v.id === versionChoice.value)
 if(!m || !v || modules.value.length >= 10 || modules.value.some(r => r.module_id === m.id)) return
 modules.value.push({ module_id: m.id, module_name: m.name, module_version_id: v.id, module_version_number: v.version_number })
}
function validate(): boolean {
  if(modules.value.length > 10 || new Set(modules.value.map(m => m.module_id)).size !== modules.value.length || modules.value.some(m => !m.module_id || !m.module_version_id)) { error.value = t('actions.invalidModules'); return false }

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
    const a = await api.updateAction(c.tenant, c.id, { runtime: 'node22', name: name.value, code: code.value, dependencies: dependencies.value.map(d => ({ ...d })), modules: modules.value.map(m => ({ ...m })), secrets: secrets.value.map(s => ({ ...s })) })
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
          <section class="card stack" :aria-label="t('actions.modules')"><h2>{{ t('actions.modules') }}</h2><p id="module-picker-hint">{{ t('actions.modulePickerHint') }}</p>
            <ul><li v-for="(m, i) in modules" :key="m.module_id">{{ m.module_name }} · {{ t('actions.versionNumber', { number: m.module_version_number }) }} <Button @click="modules.splice(i, 1)">{{ t('actions.removeModule') }}</Button></li></ul>
            <Field id="module-choice" :label="t('actions.moduleName')"><select id="module-choice" v-model="moduleChoice" aria-describedby="module-picker-hint"><option value="">—</option><option v-for="m in availableModules" :key="m.id" :value="m.id" :disabled="modules.some(r => r.module_id === m.id)">{{ m.name }}</option></select></Field>
            <Field id="module-version-choice" :label="t('actions.moduleVersion')"><select id="module-version-choice" v-model="versionChoice"><option value="">—</option><option v-for="v in moduleVersions[moduleChoice] ?? []" :key="v.id" :value="v.id">{{ v.version_number }}</option></select></Field>
            <Button :disabled="modules.length >= 10 || !versionChoice" @click="addModule">{{ t('actions.addModule') }}</Button>
          </section>
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
