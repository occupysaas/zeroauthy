<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import Button from '../../ui/Button.vue'
import PlannedPage from './PlannedPage.vue'

// Provider tiles in slice-6 order.
const providers = ['oidc', 'google', 'apple', 'facebook', 'microsoft'] as const
const { t } = useI18n()
</script>

<template>
  <PlannedPage section-key="social">
    <template #actions>
      <Button variant="primary" disabled>{{ t('plannedPreview.social.create') }}</Button>
    </template>
    <ul class="my-3 grid list-none grid-cols-[repeat(auto-fill,minmax(12rem,1fr))] gap-3 p-0">
      <li v-for="p in providers" :key="p">
        <button type="button" disabled class="w-full cursor-not-allowed rounded border border-disabled bg-disabled px-4 py-6 text-center font-sans font-bold text-disabled-text">
          {{ t(`plannedPreview.social.${p}`) }}
        </button>
      </li>
    </ul>
  </PlannedPage>
</template>
