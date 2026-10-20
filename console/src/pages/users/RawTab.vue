<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import type { User } from '../../api/client'
import CodeBlock from '../../ui/CodeBlock.vue'

const { t } = useI18n()
const props = defineProps<{ user: User }>()
const json = computed(() => JSON.stringify(props.user, null, 2))
</script>

<template>
  <CodeBlock :code="json" :title="t('userd.rawTitle')" />
</template>
