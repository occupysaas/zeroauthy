<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { TabsContent, TabsList, TabsRoot, TabsTrigger } from 'reka-ui'
import { useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import PolicyForm from './PolicyForm.vue'
import SigningKeys from './SigningKeys.vue'
import CustomSigningKeys from './CustomSigningKeys.vue'
import { settingsPanels } from './panels'
const { t } = useI18n()
const tenant = useTenant()
const tab = ref('general')
</script>
<template>
  <div v-if="tenant">
    <h1>{{ t('nav.settings') }}</h1>
    <Banner v-if="tenant.seeded" kind="warn">{{ t('seededBanner') }}</Banner>
    <TabsRoot v-model="tab">
      <TabsList class="tabs flex-wrap" :aria-label="t('nav.settings')"><TabsTrigger v-for="panel in settingsPanels" :key="panel.key" class="tab" :value="panel.key">{{ t(panel.title) }}</TabsTrigger><TabsTrigger class="tab" value="signing-keys">{{ t('signingKeys.managedTitle') }}</TabsTrigger><TabsTrigger class="tab" value="custom-signing-keys">{{ t('signingKeys.customTitle') }}</TabsTrigger></TabsList>
      <TabsContent v-for="panel in settingsPanels" :key="panel.key" :value="panel.key"><PolicyForm :tenant="tenant" :panel="panel" /></TabsContent>
      <TabsContent value="signing-keys"><SigningKeys :key="tenant.host + ':managed-signing'" :tenant="tenant" /></TabsContent>
      <TabsContent value="custom-signing-keys"><CustomSigningKeys :key="tenant.host + ':custom-signing'" :tenant="tenant" /></TabsContent>
    </TabsRoot>
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
