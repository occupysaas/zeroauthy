<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import type { Connection, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import CodeEditor from './CodeEditor.vue'
import { asRecord, mergeConfiguration, mergeOptions, optionsOf, SCRIPT_NAMES } from './options'
import ScriptTry from './ScriptTry.vue'
import StoredMark from './StoredMark.vue'

const { t } = useI18n()

const props = defineProps<{ tenant: SystemTenant; connection: Connection }>()
const emit = defineEmits<{ saved: [Connection] }>()
const { api } = useServices()

const KEY = /^[A-Za-z0-9_]{1,128}$/
const MAX_KEYS = 64
const MAX_VALUE_BYTES = 4096

const enabled = ref(false)
const importMode = ref(false)
const rootAttrs = ref('')
const scripts = reactive<Record<string, string>>({})
let savedScripts: Record<string, string> = {}
// The configuration keys the connection holds. Their values are sealed: the
// API returns opaque blobs and this page neither shows nor keeps them. What
// it keeps is which keys were replaced (with the new plaintext, until
// saved), which were removed and which are new.
const keys = ref<string[]>([])
const replaced = reactive<Record<string, string>>({})
const replacing = reactive<Record<string, boolean>>({})
const removed = ref<string[]>([])
const added = reactive<{ key: string; value: string }[]>([])
const general = ref('')
const status = ref('')
const errors = reactive<Record<string, string>>({})
const busy = ref(false)

function reset(c: Connection) {
  const o = optionsOf(c)
  enabled.value = o.enabledDatabaseCustomization === true
  importMode.value = o.import_mode === true
  rootAttrs.value = typeof o.set_user_root_attributes === 'string' ? o.set_user_root_attributes : ''
  const cs = asRecord(o.customScripts)
  savedScripts = {}
  for (const n of SCRIPT_NAMES) {
    const v = typeof cs[n] === 'string' ? (cs[n] as string) : ''
    savedScripts[n] = v
    scripts[n] = v
  }
  keys.value = Object.keys(asRecord(o.configuration))
  for (const k of Object.keys(replaced)) delete replaced[k]
  for (const k of Object.keys(replacing)) delete replacing[k]
  removed.value = []
  added.splice(0)
}
watch(() => props.connection, reset, { immediate: true })

const liveKeys = computed(() => keys.value.filter((k) => !removed.value.includes(k)))

function remove(k: string) {
  removed.value = [...removed.value, k]
  delete replaced[k]
  replacing[k] = false
}

function startReplace(k: string) {
  replacing[k] = true
  replaced[k] = ''
}

function cancelReplace(k: string) {
  replacing[k] = false
  delete replaced[k]
}

function validateConfig(): boolean {
  for (const k of Object.keys(errors)) delete errors[k]
  const seen = new Set(liveKeys.value)
  added.forEach((a, i) => {
    const key = a.key.trim()
    if (!KEY.test(key)) errors['added' + i] = t('conns.configKeyInvalid')
    else if (seen.has(key)) errors['added' + i] = t('conns.configKeyDuplicate')
    else seen.add(key)
    if (new TextEncoder().encode(a.value).length > MAX_VALUE_BYTES) errors['added' + i] = t('conns.configValueTooLong')
  })
  for (const [k, v] of Object.entries(replaced)) {
    if (new TextEncoder().encode(v).length > MAX_VALUE_BYTES) errors['replace-' + k] = t('conns.configValueTooLong')
  }
  if (seen.size > MAX_KEYS) errors.config = t('conns.configTooMany')
  return Object.keys(errors).length === 0
}

async function save() {
  general.value = ''
  status.value = ''
  if (!validateConfig()) return
  const o = optionsOf(props.connection)
  const edits: Record<string, unknown> = {
    enabledDatabaseCustomization: enabled.value,
    import_mode: importMode.value,
    set_user_root_attributes: rootAttrs.value || undefined,
  }
  const cs = Object.fromEntries(SCRIPT_NAMES.filter((n) => scripts[n]!.trim() !== '').map((n) => [n, scripts[n]!]))
  edits.customScripts = Object.keys(cs).length ? cs : undefined

  // The unchanged keys go back as the blobs the last GET returned; only
  // keys the operator set or replaced carry plaintext.
  // A replacement left empty counts as cancelled: the stored value stays.
  const plain: Record<string, string> = Object.fromEntries(Object.entries(replaced).filter(([, v]) => v !== ''))
  for (const a of added) plain[a.key.trim()] = a.value
  const config = mergeConfiguration(asRecord(o.configuration) as Record<string, string | null>, plain, removed.value)
  edits.configuration = Object.keys(config).length ? config : undefined

  busy.value = true
  try {
    const c = await api.updateConnection(props.tenant, props.connection.id, { options: mergeOptions(o, edits) })
    status.value = t('saved')
    emit('saved', c)
  } catch (e) {
    general.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <form class="stack" novalidate @submit.prevent="save">
    <Banner v-if="general" kind="error">{{ general }}</Banner>

    <section class="card stack" :aria-label="t('conns.customDb')">
      <label class="check">
        <input v-model="enabled" type="checkbox" />
        <span><strong>{{ t('conns.customEnabled') }}</strong><span class="muted">{{ t('conns.customEnabledHint') }}</span></span>
      </label>
      <label class="check">
        <input v-model="importMode" type="checkbox" />
        <span><strong>{{ t('conns.importMode') }}</strong><span class="muted">{{ t('conns.importModeHint') }}</span></span>
      </label>
      <div class="grid gap-1.5 [&>label]:font-bold">
        <label for="custom-root">{{ t('conns.rootAttrs') }}</label>
        <select id="custom-root" v-model="rootAttrs" aria-describedby="custom-root-hint">
          <option value="">{{ t('conns.rootNone') }}</option>
          <option value="on_each_login">{{ t('conns.rootEach') }}</option>
          <option value="on_first_login">{{ t('conns.rootFirst') }}</option>
          <option value="never_on_login">{{ t('conns.rootNever') }}</option>
        </select>
        <p id="custom-root-hint" class="muted m-0 text-sm">
          {{ t('conns.rootHint') }}
          <StoredMark v-if="rootAttrs === 'never_on_login'" />
        </p>
      </div>
    </section>

    <section class="card stack" :aria-label="t('conns.scripts')">
      <h2 class="m-0 text-[1.05rem]">{{ t('conns.scripts') }}</h2>
      <p class="muted">{{ t('conns.scriptsHint') }}</p>
      <details v-for="n in SCRIPT_NAMES" :key="n" class="rounded border border-hair px-3 py-2 [&_summary]:cursor-pointer" :data-testid="'script-' + n">
        <summary>
          <code>{{ n }}</code>
          <span v-if="scripts[n]!.trim()" class="muted"> · {{ t('conns.scriptSet') }}</span>
        </summary>
        <div class="stack mt-3">
          <CodeEditor :id="'script-src-' + n" v-model="scripts[n]!" :label="t('conns.scriptLabel', { name: n })" />
          <ScriptTry :tenant="tenant" :connection-id="connection.id" :script="n" :dirty="scripts[n] !== savedScripts[n]" />
        </div>
      </details>
    </section>

    <section class="card stack" :aria-label="t('conns.configuration')" data-testid="configuration">
      <h2 class="m-0 text-[1.05rem]">{{ t('conns.configuration') }}</h2>
      <p class="muted">{{ t('conns.configurationHint') }}</p>
      <p v-if="errors.config" class="m-0 text-sm text-danger" role="alert">{{ errors.config }}</p>
      <p v-if="liveKeys.length === 0 && added.length === 0" class="muted">{{ t('conns.configurationNone') }}</p>
      <ul class="m-0 grid list-none gap-2.5 p-0">
        <li v-for="k in liveKeys" :key="k" class="stack" :data-testid="'config-' + k">
          <div class="row">
            <code>{{ k }}</code>
            <span v-if="!replacing[k]" class="muted" :aria-label="t('conns.hiddenValue')">{{ t('conns.masked') }}</span>
            <span class="flex-1" />
            <template v-if="!replacing[k]">
              <Button @click="startReplace(k)">{{ t('conns.replace') }}</Button>
            </template>
            <Button v-else @click="cancelReplace(k)">{{ t('cancel') }}</Button>
            <Button variant="ghost" :aria-label="t('conns.removeKey', { key: k })" @click="remove(k)">{{ t('conns.remove') }}</Button>
          </div>
          <template v-if="replacing[k]">
            <input v-model="replaced[k]" type="password" autocomplete="new-password" :aria-label="t('conns.newValueFor', { key: k })" />
            <p v-if="errors['replace-' + k]" class="m-0 text-sm text-danger" role="alert">{{ errors['replace-' + k] }}</p>
          </template>
        </li>
        <li v-for="(a, i) in added" :key="'new' + i" class="stack" :data-testid="'config-new-' + i">
          <div class="row">
            <input v-model="a.key" type="text" :aria-label="t('conns.configKey')" autocomplete="off" spellcheck="false" />
            <input v-model="a.value" type="password" :aria-label="t('conns.configValue')" autocomplete="new-password" />
            <Button variant="ghost" @click="added.splice(i, 1)">{{ t('conns.remove') }}</Button>
          </div>
          <p v-if="errors['added' + i]" class="m-0 text-sm text-danger" role="alert">{{ errors['added' + i] }}</p>
        </li>
      </ul>
      <div class="row">
        <Button @click="added.push({ key: '', value: '' })">{{ t('conns.addKey') }}</Button>
      </div>
    </section>

    <div class="row">
      <Button variant="primary" type="submit" :disabled="busy">{{ busy ? t('saving') : t('save') }}</Button>
      <span class="muted" role="status">{{ status }}</span>
    </div>
  </form>
</template>
