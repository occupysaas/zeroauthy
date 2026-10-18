<script setup lang="ts">
withDefaults(defineProps<{ kind?: 'info' | 'warn' | 'error' }>(), { kind: 'info' })
</script>

<template>
  <div :class="['banner', kind]" :role="kind === 'error' ? 'alert' : 'status'">
    <slot />
  </div>
</template>

<style scoped>
.banner {
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 0.75rem 1rem;
  margin-bottom: 1rem;
  background: var(--accent-soft);
}
.warn {
  background: var(--warn-soft);
  border-color: var(--warn-border);
}
.error {
  background: var(--danger-soft);
  border-color: var(--danger);
}
</style>
