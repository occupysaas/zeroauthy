<script setup lang="ts">
// A table with headers and one empty-state row; planned pages never show fake rows.
defineProps<{ columns: string[]; empty: string }>()
</script>

<template>
  <table class="data">
    <thead>
      <tr><th v-for="c in columns" :key="c">{{ c }}</th></tr>
    </thead>
    <tbody>
      <tr><td :colspan="columns.length" class="text-center text-muted">{{ empty }}</td></tr>
    </tbody>
  </table>
</template>
