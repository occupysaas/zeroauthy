<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useTenant } from '../context'
import { docsURL, product, sourceURL } from '../links'
import AccountMenu from './AccountMenu.vue'
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
  <a class="skip" href="#main">{{ t('skipToContent') }}</a>
  <header class="topbar">
    <RouterLink class="brand" to="/">{{ product }}</RouterLink>
    <TenantSwitcher />
    <span class="spacer" />
    <nav class="links" aria-label="Project">
      <a :href="docsURL" target="_blank" rel="noopener noreferrer">{{ t('docs') }}</a>
      <a :href="sourceURL" target="_blank" rel="noopener noreferrer">{{ t('source') }}</a>
    </nav>
    <AccountMenu />
  </header>
  <div class="frame">
    <nav v-if="tenant" class="sidebar" aria-label="Sections">
      <ul>
        <li v-for="s in sections" :key="s.name">
          <RouterLink :to="{ name: s.name, params: { tenant: tenant.name } }" active-class="" exact-active-class="active">
            {{ s.label }}
          </RouterLink>
        </li>
      </ul>
      <p class="planned-head">{{ t('navPlanned') }}</p>
      <ul class="planned">
        <li v-for="p in planned" :key="p.key">
          <span aria-disabled="true" :title="`${p.api} (${p.when})`">{{ p.label }} <small>{{ p.when }}</small></span>
        </li>
      </ul>
    </nav>
    <main id="main" tabindex="-1">
      <RouterView />
    </main>
  </div>
</template>

<style scoped>
.planned-head {
  margin: 1rem 0 0.25rem;
  font-size: 0.75rem;
  text-transform: uppercase;
  opacity: 0.6;
}
.planned span {
  display: block;
  padding: 0.25rem 0;
  opacity: 0.5;
  cursor: not-allowed;
}
.skip {
  position: absolute;
  left: -999px;
}
.skip:focus {
  left: 1rem;
  top: 0.5rem;
  z-index: 20;
  background: var(--surface);
  padding: 0.4rem 0.8rem;
}
.topbar {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.6rem 1.25rem;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
}
.brand {
  font-weight: 700;
  font-size: 1.1rem;
  color: var(--text);
  text-decoration: none;
  letter-spacing: -0.01em;
}
.spacer {
  flex: 1;
}
.links {
  display: flex;
  gap: 1rem;
}
.frame {
  display: flex;
  min-height: calc(100vh - 3.5rem);
}
.sidebar {
  width: 13rem;
  flex-shrink: 0;
  border-right: 1px solid var(--border);
  padding: 1rem 0.5rem;
}
.sidebar ul {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  gap: 0.15rem;
}
.sidebar a {
  display: block;
  padding: 0.45rem 0.75rem;
  border-radius: 6px;
  color: var(--text);
  text-decoration: none;
}
.sidebar a.active,
.sidebar a.router-link-active {
  background: var(--accent-soft);
  font-weight: 600;
}
main {
  flex: 1;
  min-width: 0;
  padding: 1.5rem 2rem;
  max-width: 72rem;
}
main:focus {
  outline: none;
}
@media (max-width: 720px) {
  .frame {
    flex-direction: column;
  }
  .sidebar {
    width: auto;
    border-right: 0;
    border-bottom: 1px solid var(--border);
  }
  .sidebar ul {
    display: flex;
  }
  main {
    padding: 1rem;
  }
}
</style>
