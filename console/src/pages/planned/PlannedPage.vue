<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import { isPlanned, plannedWhenKey, sections } from '../../layout/sections'

// Shared frame of every planned page: breadcrumb, title, header actions, the
// planned banner and the (inert) preview in the default slot.
const props = defineProps<{ sectionKey: string }>()
const { t } = useI18n()
const section = computed(() => sections.find((s) => s.key === props.sectionKey))
const planned = computed(() => {
  const s = section.value
  return s && isPlanned(s) ? s.status : undefined
})
</script>

<template>
  <div v-if="section && planned">
    <div v-if="section.group" class="text-xs tracking-wide text-muted uppercase">{{ t(section.group) }}</div>
    <div class="mb-4 flex items-center justify-between gap-3">
      <h1 class="m-0">{{ t(section.label) }}</h1>
      <div class="flex gap-2"><slot name="actions" /></div>
    </div>
    <Banner kind="planned">
      <b class="mr-2 tracking-wide uppercase">{{ t('plannedBanner.label', { when: t(plannedWhenKey(planned)) }) }}</b>
      {{ t('plannedBanner.needs') }}
      <template v-for="(api, i) in planned.api" :key="api"><code>{{ api }}</code>{{ i < planned.api.length - 1 ? ', ' : '' }}</template>.
      {{ t('plannedBanner.note') }}
    </Banner>
    <slot v-if="$slots.default" />
    <p v-else class="my-3 text-muted">{{ t('plannedBanner.placeholder') }}</p>
  </div>
</template>
