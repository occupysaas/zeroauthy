<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ApiError, type SystemTenant, type User, type UserUpdate } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Tag from '../../ui/Tag.vue'
import CodeEditor from '../connections/CodeEditor.vue'

const { t } = useI18n()
const props = defineProps<{ tenant: SystemTenant; user: User }>()
const emit = defineEmits<{ saved: [User] }>()
const { api } = useServices()

type Kind = 'user' | 'app'
type Meta = Record<string, unknown>
const KEY = { user: 'user_metadata', app: 'app_metadata' } as const

const pretty = (m: Meta | undefined) => JSON.stringify(m ?? {}, null, 2)
const text = ref<Record<Kind, string>>({ user: '', app: '' })
const parsed = ref<Record<Kind, Meta | null>>({ user: null, app: null })
// review is the top-level merge that Save will send, shown before it is.
const review = ref<Record<Kind, Meta | null>>({ user: null, app: null })
const error = ref<Record<Kind, string>>({ user: '', app: '' })
const failure = ref<Record<Kind, string>>({ user: '', app: '' })
const status = ref<Record<Kind, string>>({ user: '', app: '' })
const busy = ref(false)
// The server answers 403 when the caller may not write app_metadata. The
// console's operator token holds every scope, so this is the fallback for a
// caller that does not: the editor turns read-only.
const appLocked = ref(false)

function reset() {
  text.value = { user: pretty(props.user.user_metadata), app: pretty(props.user.app_metadata) }
  review.value = { user: null, app: null }
}
watch(() => props.user, reset, { immediate: true })

function equal(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b)
}

// mergeOf is what PATCH needs to turn old into next: a changed or new key
// with its whole value, a removed key as null. Unchanged keys are left out.
function mergeOf(old: Meta, next: Meta): Meta {
  const out: Meta = {}
  for (const [k, v] of Object.entries(next)) if (!(k in old) || !equal(old[k], v)) out[k] = v
  for (const k of Object.keys(old)) if (!(k in next)) out[k] = null
  return out
}

function parse(kind: Kind): Meta | null {
  try {
    const v: unknown = JSON.parse(text.value[kind])
    if (v === null || typeof v !== 'object' || Array.isArray(v)) {
      error.value[kind] = t('userd.metaNotObject')
      return null
    }
    return v as Meta
  } catch {
    error.value[kind] = t('userd.metaInvalid')
    return null
  }
}

function startReview(kind: Kind) {
  error.value[kind] = ''
  failure.value[kind] = ''
  status.value[kind] = ''
  review.value[kind] = null
  const next = parse(kind)
  if (!next) return
  parsed.value[kind] = next
  review.value[kind] = mergeOf((props.user[KEY[kind]] ?? {}) as Meta, next)
}

function entries(kind: Kind) {
  const old = (props.user[KEY[kind]] ?? {}) as Meta
  return Object.entries(review.value[kind] ?? {}).map(([key, value]) => ({
    key,
    value: JSON.stringify(value),
    kind: value === null ? 'removed' : key in old ? 'changed' : 'added',
  }))
}

async function save(kind: Kind) {
  const patch = review.value[kind]
  if (!patch) return
  busy.value = true
  failure.value[kind] = ''
  try {
    const body: UserUpdate = { [KEY[kind]]: patch }
    emit('saved', await api.updateUser(props.tenant, props.user.user_id ?? '', body))
    status.value[kind] = t('saved')
  } catch (e) {
    if (kind === 'app' && e instanceof ApiError && e.status === 403) {
      appLocked.value = true
      review.value.app = null
      text.value.app = pretty(props.user.app_metadata)
    } else failure.value[kind] = errorMessage(e)
  } finally {
    busy.value = false
  }
}

const kinds = computed(() => [
  { kind: 'user' as Kind, title: t('userd.userMetadata'), hint: t('userd.userMetadataHint') },
  { kind: 'app' as Kind, title: t('userd.appMetadata'), hint: t('userd.appMetadataHint') },
])
</script>

<template>
  <div class="stack">
    <section v-for="k in kinds" :key="k.kind" class="card stack" :aria-labelledby="'meta-title-' + k.kind">
      <h2 :id="'meta-title-' + k.kind" class="m-0">{{ k.title }}</h2>
      <p class="muted m-0">{{ k.hint }}</p>
      <Banner v-if="k.kind === 'app' && appLocked" kind="warn">{{ t('userd.appLocked') }}</Banner>
      <CodeEditor :id="'user-metadata-' + k.kind" v-model="text[k.kind]" :label="k.title" :readonly="k.kind === 'app' && appLocked" />
      <p v-if="error[k.kind]" :id="'user-metadata-' + k.kind + '-error'" class="m-0 text-sm text-danger" role="alert">{{ error[k.kind] }}</p>
      <Banner v-if="failure[k.kind]" kind="error">{{ failure[k.kind] }}</Banner>
      <div v-if="review[k.kind]" :data-testid="'diff-' + k.kind" class="stack">
        <strong>{{ t('userd.diffTitle') }}</strong>
        <p v-if="entries(k.kind).length === 0" class="muted m-0">{{ t('userd.noChanges') }}</p>
        <ul v-else class="m-0 list-none p-0">
          <li v-for="e in entries(k.kind)" :key="e.key">
            <Tag class="mr-2">{{ e.kind === 'removed' ? t('userd.diff.removed') : e.kind === 'added' ? t('userd.diff.added') : t('userd.diff.changed') }}</Tag>
            <code>{{ e.key }}</code>
            <code v-if="e.kind !== 'removed'" class="muted">: {{ e.value }}</code>
          </li>
        </ul>
        <div class="row">
          <Button v-if="entries(k.kind).length > 0" variant="primary" :disabled="busy" @click="save(k.kind)">{{ t('userd.saveChanges') }}</Button>
          <Button @click="review[k.kind] = null">{{ t('cancel') }}</Button>
        </div>
      </div>
      <div v-else-if="!(k.kind === 'app' && appLocked)" class="row">
        <Button @click="startReview(k.kind)">{{ t('userd.review') }}</Button>
        <span class="muted" role="status">{{ status[k.kind] }}</span>
      </div>
    </section>
  </div>
</template>
