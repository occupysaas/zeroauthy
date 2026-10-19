<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import CopyButton from './CopyButton.vue'

const { t } = useI18n()

// A snippet to read and copy.
defineProps<{ code: string; title: string }>()
</script>

<template>
  <figure class="m-0 grid gap-1.5">
    <figcaption class="row">
      <strong>{{ title }}</strong>
      <span class="flex-1" />
      <CopyButton :value="code" :label="t('quick.copySnippet', { what: title })" />
    </figcaption>
    <pre tabindex="0" :aria-label="title" class="m-0 overflow-x-auto rounded border border-hair bg-surface px-4 py-3 text-sm"><code>{{ code }}</code></pre>
  </figure>
</template>
