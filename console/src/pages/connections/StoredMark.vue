<script setup lang="ts">
import { useI18n } from 'vue-i18n'

const { t } = useI18n()
// The marker on a setting zeroauthy keeps and returns but does not act on.
</script>

<template>
  <span class="ml-2 rounded-full border border-warn-border bg-warn-soft px-2 py-px text-xs font-bold whitespace-nowrap text-text" data-testid="not-enforced">{{ t('conns.notEnforced') }}</span>
</template>
