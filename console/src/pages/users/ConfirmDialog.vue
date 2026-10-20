<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Modal from '../../ui/Modal.vue'

const { t } = useI18n()

// A dialog that asks before something consequential. The slot holds extra
// body (a list of effects, a field to type into); confirm is disabled by the
// caller while the answer is not yet right.
withDefaults(defineProps<{ title: string; description?: string; confirmLabel: string; busy?: boolean; error?: string; disabled?: boolean; danger?: boolean }>(), { danger: true })
const open = defineModel<boolean>('open', { required: true })
defineEmits<{ confirm: [] }>()
</script>

<template>
  <Modal v-model:open="open" :title="title" :description="description">
    <form class="stack" novalidate @submit.prevent="!disabled && !busy && $emit('confirm')">
      <slot />
      <Banner v-if="error" kind="error">{{ error }}</Banner>
      <div class="row">
        <Button :variant="danger ? 'danger' : 'primary'" type="submit" :disabled="busy || disabled">{{ confirmLabel }}</Button>
        <Button @click="open = false">{{ t('cancel') }}</Button>
      </div>
    </form>
  </Modal>
</template>
