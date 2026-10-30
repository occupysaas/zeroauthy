<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import type { Confirm } from './confirm'
import ConfirmDialog from './ConfirmDialog.vue'

const { t } = useI18n()

// The modal of a useConfirm question; closing it any other way answers no.
defineProps<{ prompt: Confirm }>()
</script>

<template>
  <ConfirmDialog
    :open="prompt.open.value"
    :title="t('areYouSure')"
    :description="prompt.message.value"
    :confirm-label="prompt.label.value"
    @update:open="(v: boolean) => !v && prompt.answer(false)"
    @confirm="prompt.answer(true)"
    @closed="prompt.closed()"
  />
</template>
