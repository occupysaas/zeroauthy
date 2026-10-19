<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'
import { sections } from '../../layout/sections'

// Temporary target for every planned route until the planned pages land.
const { t } = useI18n()
const route = useRoute()
const section = sections.find((s) => s.key === route.meta.section)
</script>

<template>
  <h1>{{ section ? t(section.label) : '' }}</h1>
  <p class="my-3">{{ t('planned') }}</p>
</template>
