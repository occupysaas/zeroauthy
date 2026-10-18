<script setup lang="ts">
import { DialogClose, DialogContent, DialogDescription, DialogOverlay, DialogPortal, DialogRoot, DialogTitle } from 'reka-ui'
import { t } from '../strings'

// An accessible dialog: focus is trapped, Escape closes it, and the title
// and description are announced.
defineProps<{ title: string; description?: string }>()
const open = defineModel<boolean>('open', { required: true })
</script>

<template>
  <DialogRoot v-model:open="open">
    <DialogPortal>
      <DialogOverlay class="overlay" />
      <DialogContent class="dialog">
        <DialogTitle as="h2">{{ title }}</DialogTitle>
        <DialogDescription v-if="description" class="muted">{{ description }}</DialogDescription>
        <slot />
        <DialogClose class="visually-hidden">{{ t.close }}</DialogClose>
      </DialogContent>
    </DialogPortal>
  </DialogRoot>
</template>
