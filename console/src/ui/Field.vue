<script setup lang="ts">
// A labelled form field. The slot's control must use the given id, and
// aria-describedby for the hint and error ids.
defineProps<{ id: string; label: string; hint?: string; error?: string }>()
</script>

<template>
  <div class="field">
    <label :for="id">{{ label }}</label>
    <slot />
    <p v-if="hint" :id="id + '-hint'" class="hint">{{ hint }}</p>
    <p v-if="error" :id="id + '-error'" class="error" role="alert">{{ error }}</p>
  </div>
</template>

<style scoped>
.field {
  display: grid;
  gap: 0.3rem;
}
label {
  font-weight: 600;
}
.hint {
  margin: 0;
  color: var(--text-2);
  font-size: 0.875rem;
}
.error {
  margin: 0;
  color: var(--danger);
  font-size: 0.875rem;
}
</style>
