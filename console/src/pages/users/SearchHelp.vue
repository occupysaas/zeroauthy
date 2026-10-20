<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { userSearchDocsURL } from '../../links'

const { t } = useI18n()
const open = ref(false)

// The queries are syntax and stay as written; their captions are translated.
const examples: { query: string; label: string }[] = [
  { query: 'email:"ada@example.com"', label: t('users.helpExamples.email') },
  { query: 'email:*@example.com', label: t('users.helpExamples.domain') },
  { query: 'blocked:true', label: t('users.helpExamples.blocked') },
  { query: 'NOT _exists_:last_login', label: t('users.helpExamples.never') },
  { query: 'app_metadata.plan:"pro"', label: t('users.helpExamples.meta') },
]
</script>

<template>
  <span class="relative inline-block" @keydown.esc="open = false">
    <button
      type="button"
      class="cursor-pointer rounded border border-rule bg-surface px-3 py-1.5 font-sans font-bold text-text hover:bg-active"
      :aria-expanded="open"
      aria-controls="search-help"
      @click="open = !open"
    >
      {{ t('users.help') }}
    </button>
    <div v-if="open" id="search-help" role="region" :aria-label="t('users.help')" class="card absolute right-0 z-10 mt-1 w-96 max-w-[90vw] bg-surface">
      <p class="mt-0">{{ t('users.helpIntro') }}</p>
      <ul class="m-0 list-none p-0">
        <li v-for="e in examples" :key="e.query" class="mb-2">
          <code>{{ e.query }}</code>
          <br />
          <span class="muted">{{ e.label }}</span>
        </li>
      </ul>
      <a :href="userSearchDocsURL" target="_blank" rel="noopener noreferrer">{{ t('users.guide') }}</a>
    </div>
  </span>
</template>
