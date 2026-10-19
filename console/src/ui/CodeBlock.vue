<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import CopyButton from './CopyButton.vue'

const { t } = useI18n()

// A snippet to read and copy.
defineProps<{ code: string; title: string }>()
</script>

<template>
  <figure class="snippet">
    <figcaption class="row">
      <strong>{{ title }}</strong>
      <span class="spacer" />
      <CopyButton :value="code" :label="t('quick.copySnippet', { what: title })" />
    </figcaption>
    <pre tabindex="0" :aria-label="title"><code>{{ code }}</code></pre>
  </figure>
</template>

<style scoped>
.snippet {
  margin: 0;
  display: grid;
  gap: 0.35rem;
}
.spacer {
  flex: 1;
}
pre {
  margin: 0;
  padding: 0.75rem 1rem;
  overflow-x: auto;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  font-size: 0.85rem;
}
</style>
