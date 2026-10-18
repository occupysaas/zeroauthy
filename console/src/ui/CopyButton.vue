<script setup lang="ts">
import { ref } from 'vue'
import { t } from '../strings'
import Button from './Button.vue'

const props = defineProps<{ value: string; label?: string }>()
const done = ref(false)

async function copy() {
  try {
    await navigator.clipboard.writeText(props.value)
    done.value = true
    setTimeout(() => (done.value = false), 1500)
  } catch {
    done.value = false
  }
}
</script>

<template>
  <Button variant="ghost" :aria-label="(label ?? t.copy) + (done ? ': ' + t.copied : '')" @click="copy">
    {{ done ? t.copied : t.copy }}
  </Button>
</template>
