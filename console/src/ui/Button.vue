<script setup lang="ts">
withDefaults(
  defineProps<{
    variant?: 'primary' | 'secondary' | 'danger' | 'ghost'
    type?: 'button' | 'submit'
    disabled?: boolean
  }>(),
  { variant: 'secondary', type: 'button', disabled: false },
)
</script>

<template>
  <button :type="type" :class="['btn', variant]" :disabled="disabled">
    <slot />
  </button>
</template>

<style scoped>
.btn {
  font: inherit;
  font-weight: 600;
  border-radius: 6px;
  padding: 0.45rem 0.9rem;
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--text);
  cursor: pointer;
}
.btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
.primary {
  background: var(--accent);
  border-color: var(--accent);
  color: var(--accent-text);
}
.danger {
  background: var(--danger);
  border-color: var(--danger);
  color: var(--surface);
}
.ghost {
  border-color: transparent;
  background: transparent;
}
</style>
