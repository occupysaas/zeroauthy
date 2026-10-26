<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { TabsContent, TabsList, TabsRoot, TabsTrigger } from 'reka-ui'
import type { BrandingObject } from '../../api/client'
import { useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import Editor from './Editor.vue'
import Preview from './Preview.vue'
const { t } = useI18n()
const tenant = useTenant()
const tab = ref('branding')
const tabs = ['branding', 'theme', 'template', 'prompts', 'text', 'partials', 'preview']
const edits = ref<Record<string, { value: BrandingObject; invalid: boolean }>>({})
watch(tenant, () => { edits.value = {} })
const overrides = computed(() => Object.assign({}, ...Object.values(edits.value).map(e => e.value)) as BrandingObject)
const invalid = computed(() => Object.values(edits.value).some(e => e.invalid))
</script>
<template>
  <div v-if="tenant">
    <h1>{{ t('nav.branding') }}</h1>
    <Banner v-if="tenant.seeded" kind="warn">{{ t('seededBanner') }}</Banner>
    <Banner v-if="tenant.reserved" kind="info">{{ t('branding.reserved') }}</Banner>
    <TabsRoot v-model="tab">
      <TabsList class="tabs flex-wrap" :aria-label="t('nav.branding')"><TabsTrigger v-for="kind in tabs" :key="kind" class="tab" :value="kind">{{ t(`branding.tabs.${kind}`) }}</TabsTrigger></TabsList>
      <TabsContent v-for="kind in tabs.filter(k => k !== 'preview')" v-show="tab === kind" :key="kind" :value="kind" force-mount><Editor :key="tenant.host + kind" :kind="kind" @draft="edits[kind] = $event" /></TabsContent>
      <TabsContent value="preview" force-mount v-show="tab === 'preview'"><Preview :overrides="overrides" :invalid="invalid" /></TabsContent>
    </TabsRoot>
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
