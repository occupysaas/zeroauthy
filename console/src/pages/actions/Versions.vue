<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { ActionVersion } from '../../api/client'
import { errorMessage } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Pager from '../roles/Pager.vue'
import CodeEditor from '../connections/CodeEditor.vue'
import ActionNav from './ActionNav.vue'
import { buildStatusKey, useActionContext } from './context'
const { t } = useI18n(), { api, tenant, key, capture, current } = useActionContext()
const versions = ref<ActionVersion[]>([]), selected = ref<ActionVersion>(), page = ref(0), total = ref(0), loading = ref(false), busy = ref(false), error = ref(''), notice = ref('')
let reads = 0, inspections = 0
async function load() {
  const c = capture(), seq = ++reads
  if (!c) return
  loading.value = true; error.value = ''
  try {
    const r = await api.listActionVersions(c.tenant, c.id, { page: page.value, per_page: 20 })
    if (current(c) && seq === reads) { versions.value = r.versions; total.value = r.total }
  } catch (e) { if (current(c) && seq === reads) error.value = errorMessage(e) }
  finally { if (current(c) && seq === reads) loading.value = false }
}
watch(key, () => { versions.value = []; selected.value = undefined; page.value = 0; total.value = 0; busy.value = false; notice.value = ''; error.value = ''; ++inspections; void load() }, { immediate: true })
async function inspect(v: ActionVersion) {
  const c = capture(), seq = ++inspections
  if (!c) return
  error.value = ''; selected.value = undefined
  try { const result = await api.getActionVersion(c.tenant, c.id, v.id); if (current(c) && seq === inspections) selected.value = result }
  catch (e) { if (current(c) && seq === inspections) error.value = errorMessage(e) }
}
async function rollback(v: ActionVersion) {
  const c = capture()
  if (!c || busy.value || v.status !== 'built') return
  busy.value = true; error.value = ''; notice.value = ''
  try { await api.deployActionVersion(c.tenant, c.id, v.id); if (current(c)) notice.value = t('actions.rolledBack', { number: v.number }) }
  catch (e) { if (current(c)) error.value = errorMessage(e) }
  finally { if (current(c)) busy.value = false }
}
function goto(n: number) { page.value = n; selected.value = undefined; ++inspections; void load() }
</script>
<template>
  <div v-if="tenant" class="stack">
    <ActionNav /><h1>{{ t('actions.versions') }}</h1><p class="muted">{{ t('actions.rollbackHint') }}</p>
    <Banner v-if="error" kind="error">{{ error }} <Button @click="load">{{ t('retry') }}</Button></Banner><Banner v-if="notice">{{ notice }}</Banner>
    <p v-if="loading" role="status">{{ t('loading') }}</p>
    <table v-else-if="versions.length" class="data"><thead><tr><th scope="col">{{ t('actions.version') }}</th><th scope="col">{{ t('actions.created') }}</th><th scope="col">{{ t('actions.status') }}</th><th scope="col">{{ t('actions.manage') }}</th></tr></thead>
      <tbody><tr v-for="v in versions" :key="v.id"><td>{{ v.number }}</td><td>{{ v.created_at }}</td><td>{{ v.status ? t(buildStatusKey(v.status)) : '—' }}</td><td><div class="row"><Button @click="inspect(v)">{{ t('actions.inspect') }}</Button><Button :disabled="busy || v.status !== 'built'" @click="rollback(v)">{{ t('actions.rollback') }}</Button></div></td></tr></tbody>
    </table><p v-else class="card empty">{{ t('actions.noVersions') }}</p>
    <Pager :page="page" :total="total" :busy="loading || busy" @change="goto" />
    <section v-if="selected" class="card stack"><h2>{{ t('actions.versionNumber', { number: selected.number }) }}</h2><CodeEditor id="version-code" :model-value="selected.code" :label="t('actions.code')" readonly /><pre class="overflow-auto">{{ JSON.stringify(selected.dependencies, null, 2) }}</pre><p>{{ t('actions.secrets') }}: {{ selected.secrets.map(s => s.name).join(', ') || '—' }}</p></section>
  </div><Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
