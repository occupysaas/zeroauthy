<script setup lang="ts">
import { ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import type { Action, ActionTrigger } from '../../api/client'
import { errorMessage } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import ActionNav from './ActionNav.vue'
import { useActionContext } from './context'
const { t } = useI18n(), router = useRouter(), { api, tenant, trigger, key, capture, current } = useActionContext()
const triggers = ref<ActionTrigger[]>([]), actions = ref<Action[]>([]), bindings = ref<{ actionId: string; name: string }[]>([]), selected = ref(''), error = ref(''), notice = ref(''), busy = ref(false), loading = ref(false), reloadRequired = ref(false)
let reads = 0
async function load() {
  const c = capture(), seq = ++reads
  if (!c) return
  loading.value = true; error.value = ''
  try {
    const available = await api.listActionTriggers(c.tenant)
    if (!current(c) || seq !== reads) return
    triggers.value = available.triggers
    if (!c.trigger) return
    if (!available.triggers.some(tr => tr.id === c.trigger)) { error.value = t('actions.unsupportedTrigger'); return }
    const [list, bound] = await Promise.all([api.allActions(c.tenant, c.trigger), api.allActionBindings(c.tenant, c.trigger)])
    if (!current(c) || seq !== reads) return
    actions.value = list
    bindings.value = bound.map(b => ({ actionId: b.action.id, name: b.display_name }))
    reloadRequired.value = false
  } catch (e) { if (current(c) && seq === reads) error.value = errorMessage(e) }
  finally { if (current(c) && seq === reads) loading.value = false }
}
watch(key, () => { actions.value = []; bindings.value = []; triggers.value = []; selected.value = ''; error.value = ''; notice.value = ''; busy.value = false; reloadRequired.value = false; void load() }, { immediate: true })
function add() {
  const a = actions.value.find(a => a.id === selected.value)
  if (!a || busy.value || reloadRequired.value) return
  if (!a.deployed_version) { error.value = t('actions.undeployed'); return }
  if (bindings.value.length >= 20 || bindings.value.some(b => b.actionId === a.id)) return
  error.value = ''; notice.value = ''; bindings.value.push({ actionId: a.id, name: a.name })
}
function move(i: number, delta: number) {
  const j = i + delta
  if (busy.value || reloadRequired.value || j < 0 || j >= bindings.value.length) return
  const next = [...bindings.value], [b] = next.splice(i, 1)
  next.splice(j, 0, b!); bindings.value = next; notice.value = ''
}
function reorder(e: KeyboardEvent, i: number) {
  if (!e.altKey || !['ArrowUp', 'ArrowDown'].includes(e.key)) return
  e.preventDefault(); move(i, e.key === 'ArrowUp' ? -1 : 1)
}
async function save() {
  const c = capture()
  if (!c || !c.trigger || loading.value || busy.value || reloadRequired.value) return
  busy.value = true; error.value = ''; notice.value = ''
  try {
    const r = await api.updateActionBindings(c.tenant, c.trigger, bindings.value.map(b => ({ ref: { type: 'action_id', value: b.actionId }, display_name: b.name })))
    if (current(c)) { bindings.value = r.bindings.map(b => ({ actionId: b.action.id, name: b.display_name })); notice.value = t('actions.bindingsSaved') }
  } catch (e) { if (current(c)) { error.value = errorMessage(e); reloadRequired.value = true } }
  finally { if (current(c)) busy.value = false }
}
function selectTrigger(e: Event) { void router.push({ name: 'action-triggers', params: { tenant: tenant.value!.name, trigger: (e.target as HTMLSelectElement).value } }) }
</script>
<template>
  <div v-if="tenant" class="stack">
    <ActionNav /><h1>{{ t('actions.triggers') }}</h1><p class="muted">{{ t('actions.triggersHint') }}</p>
    <Field id="trigger-select" :label="t('actions.trigger')"><select id="trigger-select" :value="trigger" :disabled="busy" @change="selectTrigger"><option value="">{{ t('actions.chooseTrigger') }}</option><option v-for="tr in triggers" :key="tr.id" :value="tr.id">{{ tr.id }}</option></select></Field>
    <Banner v-if="error" kind="error">{{ error }} <Button v-if="!busy" @click="load">{{ t(reloadRequired ? 'actions.reloadBindings' : 'retry') }}</Button></Banner><Banner v-if="notice">{{ notice }}</Banner>
    <p v-if="loading" role="status">{{ t('loading') }}</p>
    <template v-else-if="trigger && triggers.some(tr => tr.id === trigger)">
      <section class="card stack"><h2>{{ t('actions.bindings') }}</h2><p id="binding-keyboard-hint" class="muted">{{ t('actions.reorderHint') }}</p>
        <ol class="stack pl-6"><li v-for="(b, i) in bindings" :key="b.actionId" data-testid="binding-row" tabindex="0" aria-describedby="binding-keyboard-hint" @keydown="reorder($event, i)"><div class="row flex-wrap"><span class="flex-1">{{ b.name }}</span><Button :aria-label="t('actions.up')" :disabled="busy || reloadRequired || i === 0" @click="move(i, -1)">{{ t('actions.up') }}</Button><Button :aria-label="t('actions.down')" :disabled="busy || reloadRequired || i === bindings.length - 1" @click="move(i, 1)">{{ t('actions.down') }}</Button><Button :disabled="busy || reloadRequired" :aria-label="t('actions.removeNamed', { name: b.name })" @click="bindings.splice(i, 1)">{{ t('actions.remove') }}</Button></div></li></ol>
        <p v-if="!bindings.length">{{ t('actions.noBindings') }}</p>
        <div class="row flex-wrap"><Field id="binding-action" :label="t('actions.action')"><select id="binding-action" v-model="selected" :disabled="busy || reloadRequired"><option value="">{{ t('actions.chooseAction') }}</option><option v-for="a in actions.filter(a => !bindings.some(b => b.actionId === a.id))" :key="a.id" :value="a.id">{{ a.name }}{{ a.deployed_version ? '' : ' · ' + t('actions.draft') }}</option></select></Field><Button :disabled="busy || reloadRequired || !selected || bindings.length >= 20" @click="add">{{ t('actions.addBinding') }}</Button></div>
      </section>
      <Button variant="primary" :disabled="busy || reloadRequired" @click="save">{{ t('actions.saveBindings') }}</Button>
    </template>
  </div><Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
