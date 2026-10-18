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
  <div class="editor">
    <div ref="gutter" class="gutter" aria-hidden="true" data-testid="gutter">
      <div v-for="n in count" :key="n">{{ n }}</div>
    </div>
    <textarea :id="id" v-model="model" :aria-label="label" wrap="off" spellcheck="false" autocomplete="off" rows="12" @scroll="sync" />
  </div>
</template>

<style scoped>
.editor {
  display: flex;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--surface);
  overflow: hidden;
}
.gutter,
textarea {
  font-family: var(--mono);
  font-size: 0.85rem;
  line-height: 1.4;
  padding: 0.5rem 0;
  margin: 0;
}
.gutter {
  flex-shrink: 0;
  min-width: 2.5rem;
  max-height: 17.5rem;
  overflow: hidden;
  text-align: right;
  padding-inline: 0.5rem;
  color: var(--text-2);
  background: var(--surface-2);
  user-select: none;
}
textarea {
  flex: 1;
  border: 0;
  outline-offset: -2px;
  padding-inline: 0.5rem;
  resize: vertical;
  white-space: pre;
  overflow: auto;
  max-height: 17.5rem;
  min-height: 8rem;
  background: transparent;
  color: var(--text);
}
</style>
