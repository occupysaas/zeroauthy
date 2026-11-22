<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import Field from '../../ui/Field.vue'
import ConfirmDialog from '../../ui/ConfirmDialog.vue'
import Button from '../../ui/Button.vue'
const props = defineProps<{ id: string; metadata?: Record<string, string> | null; save: (value: Record<string, string>) => Promise<void> }>()
const { t } = useI18n()
const open = ref(false), text = ref('{}'), error = ref(''), busy = ref(false)
let epoch = 0
watch(() => props.id, () => { ++epoch; open.value = false; text.value = '{}'; error.value = ''; busy.value = false })
function edit() { text.value = JSON.stringify(props.metadata ?? {}, null, 2); error.value = ''; open.value = true }
async function submit() {
  error.value = ''
  let value: unknown
  try { value = JSON.parse(text.value) } catch { error.value = t('rt48.metadataInvalid'); return }
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length > 25 || Object.entries(value).some(([k, v]) => [...k].length > 255 || typeof v !== 'string' || [...v].length > 255)) { error.value = t('rt48.metadataInvalid'); return }
  const mine = epoch
  busy.value = true
  try { await props.save(value as Record<string, string>); if (mine === epoch) open.value = false }
  catch (e) { if (mine === epoch) error.value = e instanceof Error ? e.message : String(e) }
  finally { if (mine === epoch) busy.value = false }
}
</script>
<template>
  <details><summary>{{ t('rt48.metadata') }}</summary><pre class="whitespace-pre-wrap break-all">{{ JSON.stringify(metadata ?? {}, null, 2) }}</pre></details>
  <Button :data-testid="'metadata-' + id" @click="edit">{{ t('rt48.editMetadata') }}</Button>
  <ConfirmDialog v-model:open="open" :title="t('rt48.editMetadata')" :confirm-label="t('save')" :danger="false" :busy="busy" :error="error" @confirm="submit">
    <Field :id="'metadata-value-' + id" :label="t('rt48.metadata')" :hint="t('rt48.metadataHint')"><textarea :id="'metadata-value-' + id" v-model="text" rows="8" spellcheck="false" /></Field>
  </ConfirmDialog>
</template>
