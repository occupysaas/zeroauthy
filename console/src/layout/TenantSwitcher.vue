<script setup lang="ts">
import {
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuPortal,
  DropdownMenuRoot,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from 'reka-ui'
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useTenant } from '../context'
import { useTenantsStore } from '../stores/tenants'
import { useI18n } from 'vue-i18n'
import CreateTenantDialog from './CreateTenantDialog.vue'

const { t } = useI18n()

const tenants = useTenantsStore()
const tenant = useTenant()
const route = useRoute()
const router = useRouter()
const creating = ref(false)

// switchTo keeps the section (home or applications) when it can.
function switchTo(name: string) {
  const section = route.name === 'applications' ? 'applications' : 'home'
  void router.push({ name: section, params: { tenant: name } })
}
</script>

<template>
  <DropdownMenuRoot>
    <DropdownMenuTrigger class="inline-flex min-w-0 items-center gap-1.5 cursor-pointer rounded border border-transparent bg-header-chip px-3 py-1 font-sans text-header-text hover:border-header-text" :aria-label="t('switchTenant')">
      <span class="opacity-70 max-md:hidden">{{ t('tenantLabel') }}</span>
      <strong class="truncate max-md:max-w-24">{{ tenant?.name ?? '—' }}</strong>
      <span aria-hidden="true">▾</span>
    </DropdownMenuTrigger>
    <DropdownMenuPortal>
      <DropdownMenuContent class="menu" align="start" :side-offset="6">
        <DropdownMenuLabel class="menu-label">{{ t('switchTenant') }}</DropdownMenuLabel>
        <p v-if="tenants.error" class="menu-label" role="alert">{{ tenants.error }}</p>
        <p v-else-if="tenants.list.length === 0" class="menu-label">{{ t('noTenants') }}</p>
        <DropdownMenuItem
          v-for="item in tenants.list"
          :key="item.name"
          class="menu-item data-[current]:font-bold"
          :data-current="item.name === tenant?.name || undefined"
          @select="switchTo(item.name)"
        >
          <span>{{ item.name }}</span>
          <span v-if="item.friendly_name && item.friendly_name !== item.name" class="muted">{{ item.friendly_name }}</span>
          <span v-if="item.name === tenant?.name" class="visually-hidden">{{ t('currentTenant') }}</span>
        </DropdownMenuItem>
        <DropdownMenuSeparator class="menu-sep" />
        <DropdownMenuItem class="menu-item" @select="creating = true">+ {{ t('createTenant') }}</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenuPortal>
  </DropdownMenuRoot>
  <CreateTenantDialog v-model:open="creating" />
</template>
