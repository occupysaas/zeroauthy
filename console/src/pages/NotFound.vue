<script setup lang="ts">
import { useI18n } from 'vue-i18n'

const { t } = useI18n()
</script>

<template>
  <h1>{{ t('notFoundTitle') }}</h1>
  <p>{{ t('notFoundBody') }}</p>
  <RouterLink to="/">{{ t('backHome') }}</RouterLink>
</template>
