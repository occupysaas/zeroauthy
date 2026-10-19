<script setup lang="ts">
import { useI18n } from 'vue-i18n'

const { t } = useI18n()
// The marker on a setting zeroauthy keeps and returns but does not act on.
</script>

<template>
  <span class="mark" data-testid="not-enforced">{{ t('conns.notEnforced') }}</span>
</template>

<style scoped>
.mark {
  margin-left: 0.5rem;
  font-size: 0.75rem;
  font-weight: 600;
  border: 1px solid var(--warn-border);
  background: var(--warn-soft);
  border-radius: 999px;
  padding: 0.05rem 0.5rem;
  color: var(--text);
  white-space: nowrap;
}
</style>
