<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useTenant } from '../context'
import { docsURL, product, sourceURL } from '../links'
import AccountMenu from './AccountMenu.vue'
import LanguageMenu from './LanguageMenu.vue'
import TenantSwitcher from './TenantSwitcher.vue'
import { planned } from './planned'

const { t } = useI18n()

// The frame of every signed-in page: a header with the tenant switcher and
// account menu, a sidebar with the sections this slice ships, and the page.
const tenant = useTenant()
// Operators belong to the system tenant, where the console signs in.
const sections = computed(() =>
  tenant.value
    ? [
        { name: 'home', label: t('navHome') },
        { name: 'applications', label: t('navApplications') },
        { name: 'apis', label: t('navApis') },
        { name: 'connections', label: t('navConnections') },
        ...(tenant.value.reserved ? [{ name: 'operators', label: t('navOperators') }] : []),
      ]
    : [],
)
</script>

<template>
  <a class="absolute -left-[999px] z-20 bg-surface px-3 py-1.5 focus:top-2 focus:left-4" href="#main">{{ t('skipToContent') }}</a>
  <header class="flex items-center gap-4 bg-header px-5 py-2.5 text-header-text">
    <RouterLink class="text-lg font-bold tracking-widest text-header-text uppercase no-underline hover:text-header-text" to="/">{{ product.slice(0, 4) }}<span class="text-accent">{{ product.slice(4) }}</span></RouterLink>
    <TenantSwitcher />
    <span class="flex-1" />
    <nav class="flex gap-4" :aria-label="t('navProject')">
      <a class="text-header-text no-underline hover:underline" :href="docsURL" target="_blank" rel="noopener noreferrer">{{ t('docs') }}</a>
      <a class="text-header-text no-underline hover:underline" :href="sourceURL" target="_blank" rel="noopener noreferrer">{{ t('source') }}</a>
    </nav>
    <LanguageMenu />
    <AccountMenu />
  </header>
  <div class="flex min-h-[calc(100vh-3.5rem)] max-md:flex-col">
    <nav v-if="tenant" class="w-52 shrink-0 border-r border-hair px-2 py-4 max-md:w-auto max-md:border-r-0 max-md:border-b" :aria-label="t('navSections')">
      <ul class="m-0 grid list-none gap-0.5 p-0 max-md:flex">
        <li v-for="s in sections" :key="s.name">
          <RouterLink
            class="block rounded px-3 py-2 font-bold text-text no-underline hover:bg-active aria-[current=page]:bg-active"
            :to="{ name: s.name, params: { tenant: tenant.name } }"
            active-class=""
            exact-active-class="active"
          >
            {{ s.label }}
          </RouterLink>
        </li>
      </ul>
      <p class="mt-4 mb-1 text-xs uppercase opacity-60">{{ t('navPlanned') }}</p>
      <ul class="m-0 list-none p-0">
        <li v-for="p in planned" :key="p.key">
          <span class="block cursor-not-allowed py-1 opacity-50" aria-disabled="true" :title="`${p.api} (${p.when})`">{{ p.label }} <small>{{ p.when }}</small></span>
        </li>
      </ul>
    </nav>
    <main id="main" tabindex="-1" class="max-w-6xl min-w-0 flex-1 px-8 py-6 focus:outline-none max-md:p-4">
      <RouterView />
    </main>
  </div>
</template>
