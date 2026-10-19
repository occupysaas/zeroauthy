<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import Button from './Button.vue'

const { t } = useI18n()

const props = defineProps<{ value: string; label?: string }>()
const done = ref(false)
const what = computed(() => props.label ?? t('copy'))

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
  <Button variant="ghost" :aria-label="done ? t('copyDone', { what }) : what" @click="copy">
    {{ done ? t('copied') : t('copy') }}
  </Button>
</template>
