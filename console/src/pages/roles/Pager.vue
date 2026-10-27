<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import Button from '../../ui/Button.vue'
const { t } = useI18n()
const props = defineProps<{ page: number; total: number; busy?: boolean }>()
defineEmits<{ change: [number] }>()
const from = computed(() => (props.total === 0 ? 0 : props.page * 20 + 1))
const to = computed(() => Math.min(props.total, (props.page + 1) * 20))
</script>
<template>
  <nav class="row mt-3" :aria-label="t('navPages')">
    <span class="muted" aria-live="polite">{{ t('rbac.range', { from, to, total }) }}</span>
    <span class="flex-1" />
    <Button :disabled="busy || page === 0" @click="$emit('change', page - 1)">{{ t('rbac.previous') }}</Button>
    <Button :disabled="busy || to >= total" @click="$emit('change', page + 1)">{{ t('rbac.next') }}</Button>
  </nav>
</template>
