<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { userSearchDocsURL } from '../../links'

const { t } = useI18n()
const open = ref(false)

// The queries are syntax and stay as written; their captions are translated.
const examples = computed<{ query: string; label: string }[]>(() => [
  { query: 'email:"ada@example.com"', label: t('users.helpExamples.email') },
  { query: 'email:*@example.com', label: t('users.helpExamples.domain') },
  { query: 'blocked:true', label: t('users.helpExamples.blocked') },
  { query: 'NOT _exists_:last_login', label: t('users.helpExamples.never') },
  { query: 'app_metadata.plan:"pro"', label: t('users.helpExamples.meta') },
])

const root = ref<HTMLElement | null>(null)
const toggle = ref<HTMLButtonElement | null>(null)

// Esc closes the popover and gives focus back to the button that opened it.
function onEsc() {
  if (!open.value) return
  open.value = false
  toggle.value?.focus()
}
// A click anywhere outside closes it too.
function onOutside(e: MouseEvent) {
  if (open.value && root.value && !root.value.contains(e.target as Node)) open.value = false
}
onMounted(() => document.addEventListener('click', onOutside))
onBeforeUnmount(() => document.removeEventListener('click', onOutside))
</script>

<template>
  <span ref="root" class="relative inline-block" @keydown.esc="onEsc">
    <button
      ref="toggle"
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
