<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { TabsContent, TabsList, TabsRoot, TabsTrigger } from 'reka-ui'
import { useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import Provider from './Provider.vue'
import Templates from './Templates.vue'
import Preview from './Preview.vue'

const { t } = useI18n()
const tenant = useTenant()
const tab = ref('provider')
</script>

<template>
  <div v-if="tenant">
    <h1>{{ t('emails.title') }}</h1>
    <TabsRoot v-model="tab">
      <TabsList class="tabs flex-wrap" :aria-label="t('emails.title')">
        <TabsTrigger class="tab" value="provider">{{ t('emails.providerTab') }}</TabsTrigger>
        <TabsTrigger class="tab" value="templates">{{ t('emails.templatesTab') }}</TabsTrigger>
        <TabsTrigger class="tab" value="preview">{{ t('emails.previewTab') }}</TabsTrigger>
      </TabsList>
      <TabsContent value="provider"><Provider :key="tenant.name + ':email-provider'" /></TabsContent>
      <TabsContent value="templates"><Templates :key="tenant.name + ':email-templates'" /></TabsContent>
      <TabsContent value="preview"><Preview :key="tenant.name + ':email-preview'" /></TabsContent>
    </TabsRoot>
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
