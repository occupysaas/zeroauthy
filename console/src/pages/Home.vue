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
      <dl class="facts">
        <dt>{{ t('domain') }}</dt>
        <dd class="row">
          <code>{{ tenant.host }}</code>
          <CopyButton :value="tenant.host" :label="t('domain')" />
        </dd>
        <template v-if="tenant.domains.length">
          <dt>{{ t('domains') }}</dt>
          <dd>
            <code v-for="d in tenant.domains" :key="d" class="domain">{{ d }}</code>
          </dd>
        </template>
        <dt>{{ t('discoveryURL') }}</dt>
        <dd class="row">
          <a :href="discovery" target="_blank" rel="noopener noreferrer" class="mono">{{ discovery }}</a>
          <CopyButton :value="discovery" :label="t('discoveryURL')" />
        </dd>
        <dt>{{ t('managementAPI') }}</dt>
        <dd class="row">
          <code>{{ tenant.management_api_identifier }}</code>
          <CopyButton :value="tenant.management_api_identifier" :label="t('managementAPI')" />
        </dd>
      </dl>
    </section>
    <h2>{{ t('applicationCount') }}</h2>
    <p v-if="countError" class="muted" role="alert">{{ countError }}</p>
    <p v-else>
      <RouterLink :to="{ name: 'applications', params: { tenant: tenant.name } }">
        <strong data-testid="app-count">{{ count ?? '…' }}</strong> {{ t('navApplications').toLowerCase() }}
      </RouterLink>
    </p>
    <h2>{{ t('learnMore') }}</h2>
    <ul>
      <li v-for="l in homeLinks" :key="l.href">
        <a :href="l.href" target="_blank" rel="noopener noreferrer">{{ t(l.titleKey) }}</a>
      </li>
    </ul>
  </template>
</template>

<style scoped>
.facts {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 0.5rem 1.5rem;
  margin: 0;
}
dt {
  font-weight: 600;
  color: var(--text-2);
}
dd {
  margin: 0;
}
.domain {
  display: block;
}
@media (max-width: 720px) {
  .facts {
    grid-template-columns: 1fr;
  }
}
</style>
