<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import type { components } from '../../api/schema'
const { t } = useI18n()
defineProps<{ attempts: components['schemas']['EventsEventStreamDeliveryAttempt'][] }>()
</script>
<template><div class="overflow-x-auto"><table class="data"><thead><tr><th scope="col">{{ t('events.status') }}</th><th scope="col">{{ t('events.timestamp') }}</th><th scope="col">{{ t('events.duration') }}</th><th scope="col">{{ t('events.attemptError') }}</th></tr></thead><tbody><tr v-for="(a, i) in attempts" :key="i"><td>{{ t(`events.statuses.${a.status}`) }}</td><td>{{ a.timestamp }}</td><td>{{ a.duration ?? t('events.unknown') }}</td><td>{{ a.error_message || t('events.none') }}</td></tr></tbody></table></div></template>
