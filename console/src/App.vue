<script setup lang="ts">
import { useRoute } from 'vue-router'
import Shell from './layout/Shell.vue'

const route = useRoute()
</script>

<template>
  <RouterView v-if="route.meta.bare" />
  <Shell v-else />
</template>
