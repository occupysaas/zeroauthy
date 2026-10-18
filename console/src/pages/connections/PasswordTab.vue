<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import type { Connection, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import { t } from '../../strings'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import { lines } from '../applications/defaults'
import { CHARACTER_TYPES, checkPassword, emptyProfile, type Policy, type RuleResult } from './checker'
import { asRecord, asStrings, mergeOptions, optionsOf } from './options'

const props = defineProps<{ tenant: SystemTenant; connection: Connection }>()
const emit = defineEmits<{ saved: [Connection] }>()
const { api } = useServices()

const DEFAULT_BLOCKED = ['name', 'username', 'nickname', 'email', 'phone_number', 'user_metadata.name', 'user_metadata.first', 'user_metadata.last']

const form = reactive({
  minLength: '8',
  types: [] as string[],
  rule: 'all',
  identical: 'allow',
  sequential: 'allow',
  maxExceeded: 'error',
  historyActive: false,
  historySize: '3',
  dictActive: false,
  dictDefault: 'en_100k',
  dictCustom: '',
  profileActive: false,
  blocked: DEFAULT_BLOCKED.join('\n'),
})
const errors = reactive<Record<string, string>>({})
const general = ref('')
const status = ref('')
const busy = ref(false)

function reset(c: Connection) {
  const po = asRecord(optionsOf(c).password_options)
  const cx = asRecord(po.complexity)
  const h = asRecord(po.history)
  const d = asRecord(po.dictionary)
  const p = asRecord(po.profile_data)
  form.minLength = String(typeof cx.min_length === 'number' ? cx.min_length : 8)
  form.types = asStrings(cx.character_types)
  form.rule = typeof cx.character_type_rule === 'string' ? cx.character_type_rule : 'all'
  form.identical = typeof cx.identical_characters === 'string' ? cx.identical_characters : 'allow'
  form.sequential = typeof cx.sequential_characters === 'string' ? cx.sequential_characters : 'allow'
  form.maxExceeded = typeof cx.max_length_exceeded === 'string' ? cx.max_length_exceeded : 'error'
  form.historyActive = h.active === true
  form.historySize = String(typeof h.size === 'number' ? h.size : 3)
  form.dictActive = d.active === true
  form.dictDefault = typeof d.default === 'string' ? d.default : 'en_100k'
  form.dictCustom = asStrings(d.custom).join('\n')
  form.profileActive = p.active === true
  form.blocked = (Array.isArray(p.blocked_fields) ? asStrings(p.blocked_fields) : DEFAULT_BLOCKED).join('\n')
}
watch(() => props.connection, reset, { immediate: true })

function whole(text: string, min: number, max: number): number | null {
  return /^\d+$/.test(text.trim()) && Number(text) >= min && Number(text) <= max ? Number(text) : null
}

async function save() {
  general.value = ''
  status.value = ''
  for (const k of Object.keys(errors)) delete errors[k]
  const min = whole(form.minLength, 1, 72)
  const size = whole(form.historySize, 1, 24)
  if (min === null) errors.minLength = t.conns.minLengthInvalid
  if (form.rule === 'three_of_four' && form.types.length !== CHARACTER_TYPES.length) errors.types = t.conns.threeOfFourNeedsAll
  if (size === null) errors.historySize = t.conns.historySizeInvalid
  if (Object.keys(errors).length) return

  // The whole password_options goes back: what the last GET returned, with
  // this form's values over it.
  const po = asRecord(optionsOf(props.connection).password_options)
  const next = {
    ...po,
    complexity: {
      ...asRecord(po.complexity),
      min_length: min,
      character_types: CHARACTER_TYPES.filter((x) => form.types.includes(x)),
      character_type_rule: form.rule,
      identical_characters: form.identical,
      sequential_characters: form.sequential,
      max_length_exceeded: form.maxExceeded,
    },
    history: { ...asRecord(po.history), active: form.historyActive, size },
    dictionary: { ...asRecord(po.dictionary), active: form.dictActive, default: form.dictDefault, custom: lines(form.dictCustom) },
    profile_data: { ...asRecord(po.profile_data), active: form.profileActive, blocked_fields: lines(form.blocked) },
  }
  busy.value = true
  try {
    const c = await api.updateConnection(props.tenant, props.connection.id, { options: mergeOptions(optionsOf(props.connection), { password_options: next }) })
    status.value = t.saved
    emit('saved', c)
  } catch (e) {
    general.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}

// The live checker. It reads the form as it stands, saved or not, and runs
// here: the sample password is never sent anywhere or kept.
const sample = ref('')
const profile = reactive(emptyProfile())
const policy = computed<Policy>(() => ({
  minLength: Number(form.minLength) || 0,
  characterTypes: form.types,
  characterTypeRule: form.rule === 'three_of_four' ? 'three_of_four' : 'all',
  identical: form.identical === 'block' ? 'block' : 'allow',
  sequential: form.sequential === 'block' ? 'block' : 'allow',
  maxLengthExceeded: form.maxExceeded === 'truncate' ? 'truncate' : 'error',
  dictionaryActive: form.dictActive,
  customWords: lines(form.dictCustom),
  profileActive: form.profileActive,
  blockedFields: lines(form.blocked),
}))
const results = computed<RuleResult[]>(() => checkPassword(policy.value, profile, sample.value))

function verdict(r: RuleResult): string {
  if (!r.checked) return t.conns.checker.off
  return r.ok ? t.conns.checker.pass : t.conns.checker.fail
}
function ruleLabel(r: RuleResult): string {
  if (r.rule === 'length') return r.detail === 'long' ? t.conns.checker.tooLong : t.conns.checker.minLen(Number(r.detail))
  if (r.rule === 'types' && r.checked) return policy.value.characterTypeRule === 'three_of_four' ? t.conns.checker.rules.threeOfFour : t.conns.checker.rules.types
  return t.conns.checker.rules[r.rule] ?? r.rule
}
const profileFields: { key: keyof typeof profile; label: string }[] = [
  { key: 'name', label: 'name' },
  { key: 'username', label: 'username' },
  { key: 'nickname', label: 'nickname' },
  { key: 'email', label: 'email' },
  { key: 'phone_number', label: 'phone_number' },
  { key: 'user_metadata_name', label: 'user_metadata.name' },
  { key: 'user_metadata_first', label: 'user_metadata.first' },
  { key: 'user_metadata_last', label: 'user_metadata.last' },
]
</script>

<template>
  <div class="stack">
    <form class="card stack" novalidate @submit.prevent="save">
      <Banner v-if="general" kind="error">{{ general }}</Banner>
      <h2>{{ t.conns.complexity }}</h2>
      <Field id="pw-min" :label="t.conns.minLength" :hint="t.conns.minLengthHint" :error="errors.minLength">
        <input id="pw-min" v-model="form.minLength" type="text" inputmode="numeric" :aria-invalid="!!errors.minLength" :aria-describedby="'pw-min-hint' + (errors.minLength ? ' pw-min-error' : '')" />
      </Field>
      <fieldset class="stack plain">
        <legend>{{ t.conns.characterTypes }}</legend>
        <label v-for="ct in CHARACTER_TYPES" :key="ct" class="check">
          <input v-model="form.types" type="checkbox" :value="ct" />
          <span>{{ t.conns.typeNames[ct] }}</span>
        </label>
        <p v-if="errors.types" class="error" role="alert">{{ errors.types }}</p>
      </fieldset>
      <Field id="pw-rule" :label="t.conns.typeRule" :hint="t.conns.typeRuleHint">
        <select id="pw-rule" v-model="form.rule" aria-describedby="pw-rule-hint">
          <option value="all">{{ t.conns.ruleAll }}</option>
          <option value="three_of_four">{{ t.conns.ruleThree }}</option>
        </select>
      </Field>
      <Field id="pw-identical" :label="t.conns.identical">
        <select id="pw-identical" v-model="form.identical">
          <option value="allow">{{ t.conns.allow }}</option>
          <option value="block">{{ t.conns.block }}</option>
        </select>
      </Field>
      <Field id="pw-sequential" :label="t.conns.sequential">
        <select id="pw-sequential" v-model="form.sequential">
          <option value="allow">{{ t.conns.allow }}</option>
          <option value="block">{{ t.conns.block }}</option>
        </select>
      </Field>
      <Field id="pw-max" :label="t.conns.maxExceeded" :hint="t.conns.maxExceededHint">
        <select id="pw-max" v-model="form.maxExceeded" aria-describedby="pw-max-hint">
          <option value="error">{{ t.conns.maxError }}</option>
          <option value="truncate">{{ t.conns.maxTruncate }}</option>
        </select>
      </Field>

      <h2>{{ t.conns.history }}</h2>
      <label class="check">
        <input v-model="form.historyActive" type="checkbox" />
        <span><strong>{{ t.conns.historyActive }}</strong><span class="muted">{{ t.conns.historyHint }}</span></span>
      </label>
      <Field id="pw-history-size" :label="t.conns.historySize" :error="errors.historySize">
        <input id="pw-history-size" v-model="form.historySize" type="text" inputmode="numeric" :aria-invalid="!!errors.historySize" />
      </Field>

      <h2>{{ t.conns.dictionary }}</h2>
      <label class="check">
        <input id="pw-dict-active" v-model="form.dictActive" type="checkbox" />
        <span><strong>{{ t.conns.dictActive }}</strong><span class="muted">{{ t.conns.dictHint }}</span></span>
      </label>
      <Field id="pw-dict-default" :label="t.conns.dictDefault">
        <select id="pw-dict-default" v-model="form.dictDefault">
          <option value="en_10k">{{ t.conns.dictList10k }}</option>
          <option value="en_100k">{{ t.conns.dictList100k }}</option>
        </select>
      </Field>
      <Field id="pw-dict-custom" :label="t.conns.dictCustom" :hint="t.conns.dictCustomHint">
        <textarea id="pw-dict-custom" v-model="form.dictCustom" rows="3" spellcheck="false" aria-describedby="pw-dict-custom-hint" />
      </Field>

      <h2>{{ t.conns.personal }}</h2>
      <label class="check">
        <input id="pw-profile-active" v-model="form.profileActive" type="checkbox" />
        <span><strong>{{ t.conns.personalActive }}</strong><span class="muted">{{ t.conns.personalHint }}</span></span>
      </label>
      <Field id="pw-blocked" :label="t.conns.blockedFields" :hint="t.conns.blockedFieldsHint">
        <textarea id="pw-blocked" v-model="form.blocked" rows="5" spellcheck="false" aria-describedby="pw-blocked-hint" />
      </Field>

      <div class="row">
        <Button variant="primary" type="submit" :disabled="busy">{{ busy ? t.saving : t.save }}</Button>
        <span class="muted" role="status">{{ status }}</span>
      </div>
    </form>

    <section class="card stack" :aria-label="t.conns.checker.title" data-testid="checker">
      <h2>{{ t.conns.checker.title }}</h2>
      <p class="muted">{{ t.conns.checker.intro }}</p>
      <Banner kind="info">{{ t.conns.checker.serverOnly }}</Banner>
      <Field id="pw-sample" :label="t.conns.checker.sample" :hint="t.conns.checker.sampleHint">
        <input id="pw-sample" v-model="sample" type="text" autocomplete="off" spellcheck="false" aria-describedby="pw-sample-hint" />
      </Field>
      <details>
        <summary>{{ t.conns.checker.profile }}</summary>
        <p class="muted">{{ t.conns.checker.profileHint }}</p>
        <div class="grid">
          <Field v-for="f in profileFields" :id="'pw-profile-' + f.key" :key="f.key" :label="f.label">
            <input :id="'pw-profile-' + f.key" v-model="profile[f.key]" type="text" autocomplete="off" />
          </Field>
        </div>
      </details>
      <ul class="results" aria-live="polite">
        <li v-for="r in results" :key="r.rule" :data-testid="'rule-' + r.rule" :data-state="!r.checked ? 'off' : r.ok ? 'pass' : 'fail'">
          <strong>{{ verdict(r) }}</strong> {{ ruleLabel(r) }}
        </li>
        <li data-testid="rule-history" data-state="off"><strong>{{ t.conns.checker.serverOnlyTag }}</strong> {{ t.conns.checker.rules.history }}</li>
        <li data-testid="rule-common" data-state="off"><strong>{{ t.conns.checker.serverOnlyTag }}</strong> {{ t.conns.checker.rules.common }}</li>
      </ul>
    </section>
  </div>
</template>

<style scoped>
h2 {
  margin: 0;
  font-size: 1.05rem;
}
.check {
  display: flex;
  gap: 0.6rem;
  align-items: flex-start;
}
.check > span {
  display: grid;
}
.check input {
  margin-top: 0.3rem;
}
.plain {
  border: 0;
  padding: 0;
  margin: 0;
}
.plain legend {
  font-weight: 600;
  padding: 0;
}
.error {
  margin: 0;
  color: var(--danger);
  font-size: 0.875rem;
}
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr));
  gap: 0.75rem;
}
.results {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  gap: 0.35rem;
}
.results li[data-state='pass'] strong {
  color: var(--accent);
}
.results li[data-state='fail'] strong {
  color: var(--danger);
}
.results li[data-state='off'] {
  color: var(--text-2);
}
</style>
