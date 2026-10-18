<script setup lang="ts">
import type { ResourceServerScope } from '../../api/client'
import { t } from '../../strings'

// Which of an API's permissions a grant carries. "All" grants every
// permission the API defines when a token is issued.
defineProps<{ id: string; scopes: ResourceServerScope[]; disabled?: boolean }>()
const selected = defineModel<string[]>('selected', { required: true })
const all = defineModel<boolean>('all', { required: true })

function toggle(value: string, on: boolean) {
  selected.value = on ? [...selected.value, value] : selected.value.filter((v) => v !== value)
}
</script>

<template>
  <fieldset class="picker">
    <legend class="visually-hidden">{{ t.apis.permissions }}</legend>
    <p v-if="scopes.length === 0" class="muted">{{ t.apis.grantNoScopes }}</p>
    <template v-else>
      <label class="opt">
        <input v-model="all" type="checkbox" :disabled="disabled" :data-testid="id + '-all'" />
        <span>{{ t.apis.allScopes }}</span>
      </label>
      <label v-for="s in scopes" :key="s.value" class="opt">
        <input
          type="checkbox"
          :value="s.value"
          :checked="all || selected.includes(s.value)"
          :disabled="disabled || all"
          @change="toggle(s.value, ($event.target as HTMLInputElement).checked)"
        />
        <span>
          <code>{{ s.value }}</code>
          <span v-if="s.description" class="muted"> {{ s.description }}</span>
        </span>
      </label>
    </template>
  </fieldset>
</template>

<style scoped>
.picker {
  border: 0;
  margin: 0;
  padding: 0;
  display: grid;
  gap: 0.35rem;
}
.opt {
  display: flex;
  gap: 0.5rem;
  align-items: flex-start;
}
.opt input {
  margin-top: 0.3rem;
}
</style>
