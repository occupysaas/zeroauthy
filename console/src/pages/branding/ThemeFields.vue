<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import Field from '../../ui/Field.vue'
import { activeThemeFields, type ThemeField } from './fields'
const props = defineProps<{ modelValue: string; disabled: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [string] }>()
const { t } = useI18n()
const parsed = computed<Record<string, unknown> | undefined>(() => {
  try { const value: unknown = JSON.parse(props.modelValue); return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined } catch { return undefined }
})
function read(path: string): string | number {
  let value: unknown = parsed.value
  for (const name of path.split('.')) value = value && typeof value === 'object' ? (value as Record<string, unknown>)[name] : undefined
  return value == null ? '' : typeof value === 'number' ? value : String(value)
}
function update(field: ThemeField, event: Event) {
  if (!parsed.value) return
  const result = JSON.parse(JSON.stringify(parsed.value)) as Record<string, unknown>
  const parts = field.path.split('.')
  let node = result
  for (const name of parts.slice(0, -1)) {
    if (!node[name] || typeof node[name] !== 'object') node[name] = {}
    node = node[name] as Record<string, unknown>
  }
  const input = (event.target as HTMLInputElement).value
  node[parts.at(-1)!] = input === '' ? null : field.kind === 'number' ? Number(input) : field.kind === 'boolean' ? input === 'true' : input
  emit('update:modelValue', JSON.stringify(result, null, 2))
}
</script>
<template>
  <fieldset class="grid gap-4 border-0 p-0 sm:grid-cols-2" :disabled="disabled || !parsed">
    <legend>{{ t('branding.components') }}</legend>
    <p v-if="!parsed">{{ t('branding.invalidJSON') }}</p>
    <Field v-for="field in activeThemeFields" :id="'theme-' + field.path.replaceAll('.', '-')" :key="field.path" :label="t(`branding.themeLabels.${field.path.replaceAll('.', '_')}`)">
      <select v-if="field.options || field.kind === 'boolean'" :id="'theme-' + field.path.replaceAll('.', '-')" :value="read(field.path)" @change="update(field, $event)">
        <option value="">{{ t('branding.inherit') }}</option>
        <template v-if="field.kind === 'boolean'"><option value="true">{{ t('branding.yes') }}</option><option value="false">{{ t('branding.no') }}</option></template>
        <option v-for="option in field.options" v-else :key="option" :value="option">{{ option }}</option>
      </select>
      <input v-else :id="'theme-' + field.path.replaceAll('.', '-')" :type="field.kind === 'number' ? 'number' : 'text'" :value="read(field.path)" :min="field.min" :max="field.max" :placeholder="t('branding.inherit')" @input="update(field, $event)" />
    </Field>
  </fieldset>
</template>
