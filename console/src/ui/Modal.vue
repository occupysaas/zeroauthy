<script setup lang="ts">
import { DialogClose, DialogContent, DialogDescription, DialogOverlay, DialogPortal, DialogRoot, DialogTitle } from 'reka-ui'
import { useTemplateRef, watch } from 'vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

// An accessible dialog: focus is trapped, Escape closes it, and the title
// and description are announced. Only the X, Escape or the caller's own
// cancel button close it: a click outside never throws a form away. The
// header stays put while a long body scrolls.
const props = defineProps<{ title: string; description?: string; wide?: boolean }>()
const open = defineModel<boolean>('open', { required: true })
// closed follows a close once the dialog is gone and focus is back.
const emit = defineEmits<{ closed: [] }>()

// Closing returns focus to what had it when the dialog opened, while that
// is still on the page and can take it.
let returnTo: HTMLElement | null = null
watch(open, (v) => { if (v) returnTo = document.activeElement instanceof HTMLElement ? document.activeElement : null }, { immediate: true })
// A form starts at its first field rather than at the X. Wide modals hold
// whole edit pages, so they start at the top.
const body = useTemplateRef<HTMLElement>('body')
function focusFirstField(e: Event) {
  if (props.wide) return
  const field = body.value?.querySelector<HTMLElement>('input:not([type=hidden]):not([type=radio]):not([type=checkbox]):not([disabled]):not([readonly]), select:not([disabled]), textarea:not([disabled])')
  if (!field) return
  e.preventDefault()
  field.focus()
}
function restoreFocus(e: Event) {
  if (returnTo?.isConnected) {
    e.preventDefault()
    returnTo.focus()
  }
  emit('closed')
}
</script>

<template>
  <DialogRoot v-model:open="open">
    <DialogPortal>
      <DialogOverlay class="overlay" />
      <DialogContent class="dialog" :class="{ wide }" @interact-outside.prevent @open-auto-focus="focusFirstField" @close-auto-focus="restoreFocus">
        <div class="dialog-head">
          <DialogTitle as="h2">{{ title }}</DialogTitle>
          <DialogClose class="dialog-close" :aria-label="t('close')"><span aria-hidden="true">×</span></DialogClose>
        </div>
        <div ref="body" class="dialog-body">
          <DialogDescription v-if="description" class="muted">{{ description }}</DialogDescription>
          <slot />
        </div>
      </DialogContent>
    </DialogPortal>
  </DialogRoot>
</template>
