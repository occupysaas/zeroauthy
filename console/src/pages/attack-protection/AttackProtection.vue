<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { TabsContent, TabsList, TabsRoot, TabsTrigger } from 'reka-ui'
import { useTenant } from '../../context'
import Banner from '../../ui/Banner.vue'
import PolicyForm from '../settings/PolicyForm.vue'
import BlocksPanel from '../users/BlocksPanel.vue'
import { protectionPanels } from './panels'
const { t } = useI18n()
const tenant = useTenant()
const tab = ref('brute')
</script>
<template>
  <div v-if="tenant">
    <h1>{{ t('nav.attackProtection') }}</h1>
    <Banner v-if="tenant.seeded" kind="warn">{{ t('seededBanner') }}</Banner>
    <TabsRoot v-model="tab">
      <TabsList class="tabs flex-wrap" :aria-label="t('nav.attackProtection')"><TabsTrigger v-for="panel in protectionPanels" :key="panel.key" class="tab" :value="panel.key">{{ t(panel.title) }}</TabsTrigger><TabsTrigger class="tab" value="blocks">{{ t('policy.ipBlocks') }}</TabsTrigger></TabsList>
      <TabsContent v-for="panel in protectionPanels" :key="panel.key" :value="panel.key">
        <Banner v-if="panel.key === 'breach'" :kind="tenant.breached_password_checker?.available ? 'info' : 'warn'">{{ t(tenant.breached_password_checker?.available ? 'policy.checkerAvailable' : 'policy.checkerUnavailable') }}</Banner>
        <PolicyForm :tenant="tenant" :panel="panel" />
      </TabsContent>
      <TabsContent value="blocks"><BlocksPanel :tenant="tenant" /></TabsContent>
    </TabsRoot>
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
