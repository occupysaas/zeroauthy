<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { ActionModule, ActionModuleRef, ActionModuleVersion, Action } from '../../api/client'
import { errorMessage } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import ScriptEditor from '../connections/social/ScriptEditor.vue'
import DraftConfiguration from './DraftConfiguration.vue'
import { useDraftEditor } from './useDraftEditor'
import ActionNav from './ActionNav.vue'
import { buildStatusKey, useActionContext } from './context'
const { t } = useI18n(), ctx = useActionContext(), { api, tenant, capture, current } = ctx
const modules = ref<ActionModuleRef[]>([]), availableModules = ref<ActionModule[]>([]), moduleVersions = ref<Record<string, ActionModuleVersion[]>>({}), moduleChoice = ref(''), versionChoice = ref('')
let moduleReads = 0
const { resource: action, name, code, dependencies, secrets, loading, busy, error, notice, reloadRequired, dirty, read, save, reload, publish: deploy } = useDraftEditor<Action>({
 context: ctx,
 limits: { name: 128, code: 100000, codeUnit: 'bytes', invalid: 'actions.invalidDraft' },
 read: (tenant, id) => api.getAction(tenant, id),
 update: (tenant, id, draft) => api.updateAction(tenant, id, { ...draft, runtime: 'node22', modules: modules.value.map(m => ({ ...m })) }),
 publish: async (tenant, id, value) => ({ ...value, deployed_version: await api.deployAction(tenant, id), all_changes_deployed: true }),
 published: 'actions.deployed', extraDraft: () => modules.value,
 applyExtra: value => { modules.value = (value.modules ?? []).map(m => ({ ...m })) },
 validateExtra: () => modules.value.length > 10 || new Set(modules.value.map(m => m.module_id)).size !== modules.value.length || modules.value.some(m => !m.module_id || !m.module_version_id) ? 'actions.invalidModules' : undefined,
 resetExtra: () => { ++moduleReads; modules.value = []; availableModules.value = []; moduleVersions.value = {}; moduleChoice.value = ''; versionChoice.value = ''; void loadModules() },
})
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
          <DraftConfiguration v-model:dependencies="dependencies" v-model:secrets="secrets" />
        </fieldset>
        <div class="row"><Button type="submit" variant="primary" :disabled="busy || reloadRequired">{{ t('actions.save') }}</Button><Button v-if="reloadRequired" :disabled="busy" @click="reload">{{ t('actions.reload') }}</Button></div>
        <p v-if="reloadRequired" class="muted">{{ t('actions.reloadHint') }}</p>
      </form>
    </template>
    <Button v-else-if="error" @click="read()">{{ t('retry') }}</Button>
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
