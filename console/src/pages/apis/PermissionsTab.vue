<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { ApiError, type ResourceServer, type ResourceServerScope, type SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import Modal from '../../ui/Modal.vue'

const { t } = useI18n()

const props = defineProps<{ tenant: SystemTenant; server: ResourceServer }>()
const emit = defineEmits<{ saved: [ResourceServer] }>()
const { api } = useServices()

const scopes = ref<ResourceServerScope[]>([])
const value = ref('')
const description = ref('')
const errors = reactive<Record<string, string>>({})
const general = ref('')
const status = ref('')
const busy = ref(false)
// Removing permissions that grants carry waits for a confirmation.
const confirming = ref(false)
const affected = ref(0)

watch(
  () => props.server,
  (s) => (scopes.value = (s.scopes ?? []).map((x) => ({ ...x }))),
  { immediate: true },
)

const saved = computed(() => props.server.scopes ?? [])
const removed = computed(() => saved.value.map((s) => s.value).filter((v) => !scopes.value.some((s) => s.value === v)))
const dirty = computed(() => JSON.stringify(scopes.value) !== JSON.stringify(saved.value))

// The prompt before saving names the permissions that are in use and how many grants carry them.
const scopesInUse = computed(() => {
  const key = `apis.scopesInUse.${removed.value.length === 1 ? 'one' : 'many'}${affected.value === 1 ? 'One' : 'Many'}` as const
  return t(key, { values: removed.value.join(', '), grants: affected.value })
})

function add() {
  for (const k of Object.keys(errors)) delete errors[k]
  const v = value.value.trim()
  if (!v) errors.value = t('apis.scopeValueRequired')
  else if (v.length > 280) errors.value = t('apis.scopeValueTooLong')
  else if (scopes.value.some((s) => s.value === v)) errors.value = t('apis.scopeDuplicate')
  if (description.value.length > 500) errors.description = t('apis.scopeDescriptionTooLong')
  if (Object.keys(errors).length) return
  scopes.value.push(description.value.trim() ? { value: v, description: description.value.trim() } : { value: v })
  value.value = ''
  description.value = ''
  status.value = ''
}

function remove(v: string) {
  scopes.value = scopes.value.filter((s) => s.value !== v)
  status.value = ''
}

// save asks first when a removed permission is carried by a client grant.
async function save() {
  general.value = ''
  status.value = ''
  if (removed.value.length) {
    busy.value = true
    try {
      const grants = await api.allClientGrants(props.tenant, { audience: props.server.identifier })
      affected.value = grants.filter((g) => g.scope?.some((s) => removed.value.includes(s))).length
    } catch (e) {
      general.value = errorMessage(e)
      busy.value = false
      return
    }
    busy.value = false
    if (affected.value > 0) {
      confirming.value = true
      return
    }
  }
  await commit()
}

async function commit() {
  busy.value = true
  try {
    const s = await api.updateResourceServer(props.tenant, props.server.id, { scopes: scopes.value })
    confirming.value = false
    status.value = t('saved')
    emit('saved', s)
  } catch (e) {
    confirming.value = false
    general.value = e instanceof ApiError ? e.message : errorMessage(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="stack">
    <Banner v-if="server.is_system" kind="info">{{ t('apis.systemNote') }}</Banner>
    <section class="card stack">
      <p class="muted">{{ t('apis.permissionsHint') }}</p>
      <Banner v-if="general" kind="error">{{ general }}</Banner>
      <p v-if="scopes.length === 0" class="muted" data-testid="scopes-empty">{{ t('apis.scopesEmpty') }}</p>
      <table v-else class="data">
        <thead>
          <tr>
            <th scope="col">{{ t('apis.scopeValue') }}</th>
            <th scope="col">{{ t('apis.scopeDescription') }}</th>
            <td v-if="!server.is_system" />
          </tr>
        </thead>
        <tbody>
          <tr v-for="s in scopes" :key="s.value">
            <td><code>{{ s.value }}</code></td>
            <td>{{ s.description }}</td>
            <td v-if="!server.is_system">
              <Button variant="ghost" :aria-label="t('apis.scopeRemoveLabel', { value: s.value })" @click="remove(s.value)">{{ t('apis.scopeRemove') }}</Button>
            </td>
          </tr>
        </tbody>
      </table>
    </section>

    <template v-if="!server.is_system">
      <form class="card stack" novalidate @submit.prevent="add">
        <Field id="scope-value" :label="t('apis.scopeValue')" :hint="t('apis.scopeValueHint')" :error="errors.value">
          <input id="scope-value" v-model="value" type="text" autocomplete="off" spellcheck="false" :aria-invalid="!!errors.value" aria-describedby="scope-value-hint" />
        </Field>
        <Field id="scope-description" :label="t('apis.scopeDescription')" :error="errors.description">
          <input id="scope-description" v-model="description" type="text" autocomplete="off" :aria-invalid="!!errors.description" />
        </Field>
        <div class="row">
          <Button type="submit">{{ t('apis.scopeAdd') }}</Button>
        </div>
      </form>
      <div class="row">
        <Button variant="primary" :disabled="busy || !dirty" @click="save">{{ busy ? t('saving') : t('apis.scopesSave') }}</Button>
        <span v-if="dirty" class="muted">{{ t('apis.scopesUnsaved') }}</span>
        <span class="muted" role="status">{{ status }}</span>
      </div>
    </template>

    <Modal v-model:open="confirming" :title="t('apis.scopesInUseTitle')" :description="scopesInUse">
      <div class="row">
        <Button variant="danger" :disabled="busy" @click="commit">{{ t('apis.scopesInUseConfirm') }}</Button>
        <Button @click="confirming = false">{{ t('cancel') }}</Button>
      </div>
    </Modal>
  </div>
</template>
