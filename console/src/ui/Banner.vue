<script setup lang="ts">
withDefaults(defineProps<{ kind?: 'info' | 'warn' | 'error' | 'planned' }>(), { kind: 'info' })

const kinds = {
  info: 'border border-hair bg-active',
  warn: 'border border-warn-border bg-warn-soft',
  error: 'border border-danger bg-danger-soft',
  planned: 'border-2 border-rule bg-surface',
}
</script>

<template>
  <div :class="['mb-4 rounded px-4 py-3', kinds[kind]]" :role="kind === 'error' ? 'alert' : 'status'">
    <slot />
  </div>
</template>
