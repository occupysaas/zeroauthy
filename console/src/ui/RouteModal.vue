<script setup lang="ts">
import { useRoute, useRouter } from 'vue-router'
import Modal from './Modal.vue'

// A modal that is a route of its own: a create or edit form shown over the
// list it belongs to, so the sidebar keeps its place. Closing it goes back
// to that list; the slot's close does the same for a cancel button.
const props = defineProps<{ title: string; back: string; wide?: boolean }>()
const route = useRoute()
const router = useRouter()

function close(open: boolean) {
  if (!open) void router.push({ name: props.back, params: { tenant: route.params.tenant } })
}
</script>

<template>
  <Modal :open="true" :title="title" :wide="wide" @update:open="close"><slot :close="() => close(false)" /></Modal>
</template>
