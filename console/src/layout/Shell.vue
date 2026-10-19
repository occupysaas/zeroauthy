<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, useTemplateRef, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'
import { useTenant } from '../context'
import { docsURL, productParts, sourceURL } from '../links'
import Tag from '../ui/Tag.vue'
import AccountMenu from './AccountMenu.vue'
import LanguageMenu from './LanguageMenu.vue'
import { isPlanned, plannedWhenKey, visibleSections, type Section } from './sections'
import TenantSwitcher from './TenantSwitcher.vue'

const { t } = useI18n()

// The frame of every signed-in page: a header with the tenant switcher and
// account menu, a grouped sidebar of every section, and the page. Below the
// md breakpoint the sidebar is a drawer behind the header's menu button.
const tenant = useTenant()
const route = useRoute()

// Consecutive sections of one group share a heading; Home has none.
const groups = computed(() => {
  const out: { group?: string; items: Section[] }[] = []
  for (const s of visibleSections(tenant.value?.reserved ?? false)) {
    const last = out[out.length - 1]
    if (last && last.group === s.group) last.items.push(s)
    else out.push({ group: s.group, items: [s] })
  }
  return out
})

function tip(s: Section): string | undefined {
  return isPlanned(s) ? t('plannedTip', { when: t(plannedWhenKey(s.status)), apis: s.status.api.join(', ') }) : undefined
}

const open = ref(false)
const button = useTemplateRef<HTMLButtonElement>('menuButton')
const sidebar = useTemplateRef<HTMLElement>('sidebar')

async function toggle() {
  open.value = !open.value
  if (!open.value) return
  await nextTick()
  sidebar.value?.querySelector('a')?.focus()
}

function close() {
  if (!open.value) return
  open.value = false
  button.value?.focus()
}

function onKey(e: KeyboardEvent) {
  if (e.key === 'Escape' && !e.defaultPrevented) close()
}
onMounted(() => document.addEventListener('keydown', onKey))
onBeforeUnmount(() => document.removeEventListener('keydown', onKey))
watch(() => route.fullPath, close)
</script>

<template>
  <a class="absolute -left-[999px] z-20 bg-surface px-3 py-1.5 focus:top-2 focus:left-4" href="#main">{{ t('skipToContent') }}</a>
  <header class="flex items-center gap-4 bg-header px-5 py-2.5 text-header-text max-md:gap-2 max-md:px-3">
    <button
      v-if="tenant"
      ref="menuButton"
      type="button"
      class="rounded border border-header-chip bg-transparent px-2.5 py-1 text-header-text md:hidden"
      aria-controls="sections-nav"
      :aria-expanded="open"
      @click="toggle"
    >
      {{ t('menu') }}
    </button>
    <RouterLink class="text-lg font-bold tracking-widest text-header-text uppercase no-underline hover:text-header-text" to="/">{{ productParts[0] }}<span class="text-accent">{{ productParts[1] }}</span></RouterLink>
    <TenantSwitcher />
    <span class="flex-1" />
    <nav class="flex gap-4 max-md:hidden" :aria-label="t('navProject')">
      <a class="text-header-text no-underline hover:underline" :href="docsURL" target="_blank" rel="noopener noreferrer">{{ t('docs') }}</a>
      <a class="text-header-text no-underline hover:underline" :href="sourceURL" target="_blank" rel="noopener noreferrer">{{ t('source') }}</a>
    </nav>
    <LanguageMenu />
    <AccountMenu />
  </header>
  <div class="flex min-h-[calc(100vh-3.5rem)] max-md:flex-col">
    <nav
      v-if="tenant"
      id="sections-nav"
      ref="sidebar"
      class="w-56 shrink-0 border-r-[3px] border-rule px-2 py-4 max-md:w-auto max-md:border-r-0 max-md:border-b-[3px]"
      :class="{ 'max-md:hidden': !open }"
      :aria-label="t('navSections')"
    >
      <ul class="m-0 grid list-none gap-0.5 p-0">
        <template v-for="g in groups" :key="g.group ?? ''">
          <li v-if="g.group">
            <h2 class="mt-4 mb-1 px-3 text-xs font-normal tracking-widest text-muted uppercase">{{ t(g.group) }}</h2>
          </li>
          <li v-for="s in g.items" :key="s.key">
            <RouterLink
              class="flex items-center gap-2 border-l-[3px] border-transparent px-3 py-2 font-bold text-text no-underline hover:bg-active aria-[current=page]:border-accent aria-[current=page]:bg-active"
              :to="{ name: s.key, params: { tenant: tenant.name } }"
              :title="tip(s)"
              active-class=""
              exact-active-class="active"
            >
              <span>{{ t(s.label) }}</span>
              <Tag v-if="isPlanned(s)">{{ t('planned') }}</Tag>
            </RouterLink>
          </li>
        </template>
        <li class="mt-4 border-t border-rule pt-2 md:hidden">
          <a class="block px-3 py-2 font-bold text-text no-underline hover:bg-active" :href="docsURL" target="_blank" rel="noopener noreferrer">{{ t('docs') }}</a>
          <a class="block px-3 py-2 font-bold text-text no-underline hover:bg-active" :href="sourceURL" target="_blank" rel="noopener noreferrer">{{ t('source') }}</a>
        </li>
      </ul>
    </nav>
    <main id="main" tabindex="-1" class="max-w-6xl min-w-0 flex-1 px-8 py-6 focus:outline-none max-md:p-4">
      <RouterView />
    </main>
  </div>
</template>
