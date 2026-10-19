<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { errorMessage, useServices, useTenant } from '../context'
import { useI18n } from 'vue-i18n'
import { homeLinks } from '../links'
import Banner from '../ui/Banner.vue'
import CopyButton from '../ui/CopyButton.vue'

const { t } = useI18n()

const { api } = useServices()
const tenant = useTenant()
const count = ref<number | null>(null)
const countError = ref('')

const discovery = computed(() => (tenant.value ? 'https://' + tenant.value.host + '/.well-known/openid-configuration' : ''))

watch(
  tenant,
  async (tn) => {
    count.value = null
    countError.value = ''
    if (!tn) return
    try {
      count.value = (await api.listClients(tn, { page: 0, per_page: 1 })).total
    } catch (e) {
      countError.value = errorMessage(e)
    }
  },
  { immediate: true },
)
</script>

<template>
  <Banner v-if="!tenant" kind="error">{{ t('unknownTenant') }}</Banner>
  <template v-else>
    <h1>{{ tenant.friendly_name || tenant.name }}</h1>
    <Banner v-if="tenant.seeded" kind="warn">{{ t('seededBanner') }}</Banner>
    <section class="card stack" aria-labelledby="home-tenant">
      <h2 id="home-tenant" class="visually-hidden">{{ t('tenant') }}</h2>
      <dl class="m-0 grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2 max-md:grid-cols-1">
        <dt class="font-bold text-muted">{{ t('domain') }}</dt>
        <dd class="row m-0">
          <code>{{ tenant.host }}</code>
          <CopyButton :value="tenant.host" :label="t('domain')" />
        </dd>
        <template v-if="tenant.domains.length">
          <dt class="font-bold text-muted">{{ t('domains') }}</dt>
          <dd class="m-0">
            <code v-for="d in tenant.domains" :key="d" class="block">{{ d }}</code>
          </dd>
        </template>
        <dt class="font-bold text-muted">{{ t('discoveryURL') }}</dt>
        <dd class="row m-0">
          <a :href="discovery" target="_blank" rel="noopener noreferrer" class="mono">{{ discovery }}</a>
          <CopyButton :value="discovery" :label="t('discoveryURL')" />
        </dd>
        <dt class="font-bold text-muted">{{ t('managementAPI') }}</dt>
        <dd class="row m-0">
          <code>{{ tenant.management_api_identifier }}</code>
          <CopyButton :value="tenant.management_api_identifier" :label="t('managementAPI')" />
        </dd>
      </dl>
    </section>
    <h2>{{ t('applicationCount') }}</h2>
    <p v-if="countError" class="muted" role="alert">{{ countError }}</p>
    <p v-else>
      <RouterLink :to="{ name: 'applications', params: { tenant: tenant.name } }">
        <i18n-t keypath="appCount" scope="global" tag="span">
          <template #count>
            <strong data-testid="app-count">{{ count ?? '…' }}</strong>
          </template>
        </i18n-t>
      </RouterLink>
    </p>
    <h2>{{ t('learnMore') }}</h2>
    <ul class="m-0 list-disc pl-6">
      <li v-for="l in homeLinks" :key="l.href">
        <a :href="l.href" target="_blank" rel="noopener noreferrer">{{ t(l.titleKey) }}</a>
      </li>
    </ul>
  </template>
</template>
