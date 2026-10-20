<script setup lang="ts">
// Placeholder until the user detail page (Task 13) replaces it: it gives
// the create page somewhere to go.
import { useRoute } from 'vue-router'

const route = useRoute()
</script>

<template>
  <h1>{{ String(route.params.id) }}</h1>
</template>
