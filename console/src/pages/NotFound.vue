<script setup lang="ts">
import { t } from '../strings'
</script>

<template>
  <h1>{{ t.notFoundTitle }}</h1>
  <p>{{ t.notFoundBody }}</p>
  <RouterLink to="/">{{ t.backHome }}</RouterLink>
</template>
