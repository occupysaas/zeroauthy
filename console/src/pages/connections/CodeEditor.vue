<script setup lang="ts">
import { computed, ref } from 'vue'

// A monospace textarea with line numbers; no editor dependency.
defineProps<{ id: string; label: string }>()
const model = defineModel<string>({ required: true })
const gutter = ref<HTMLElement | null>(null)
const count = computed(() => Math.max(1, model.value.split('\n').length))

function sync(e: Event) {
  if (gutter.value) gutter.value.scrollTop = (e.target as HTMLElement).scrollTop
}
</script>

<template>
  <div class="flex overflow-hidden rounded border border-rule bg-surface">
    <div ref="gutter" class="m-0 max-h-70 min-w-10 shrink-0 overflow-hidden bg-tag px-2 py-2 text-right font-mono text-[0.85rem] leading-[1.4] text-muted select-none" aria-hidden="true" data-testid="gutter">
      <div v-for="n in count" :key="n">{{ n }}</div>
    </div>
    <textarea
      :id="id" v-model="model" :aria-label="label" class="m-0 max-h-70 min-h-32 min-w-0 flex-1 resize-y overflow-auto rounded-none border-0 bg-transparent px-2 py-2 font-mono text-[0.85rem] leading-[1.4] whitespace-pre text-text -outline-offset-2"
      wrap="off"
      spellcheck="false"
      autocomplete="off"
      rows="12"
      @scroll="sync"
    />
  </div>
</template>
