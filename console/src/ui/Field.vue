<script setup lang="ts">
// A labelled form field. The slot's control must use the given id, and
// aria-describedby for the hint and error ids.
defineProps<{ id: string; label: string; hint?: string; error?: string }>()
</script>

<template>
  <div class="grid gap-1">
    <label :for="id" class="font-bold">{{ label }}</label>
    <slot />
    <p v-if="hint" :id="id + '-hint'" class="m-0 text-sm text-muted">{{ hint }}</p>
    <p v-if="error" :id="id + '-error'" class="m-0 text-sm text-danger" role="alert">{{ error }}</p>
  </div>
</template>
