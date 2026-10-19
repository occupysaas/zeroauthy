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
    <DropdownMenuTrigger class="trigger" :aria-label="t('switchTenant')">
      <span class="muted">{{ t('tenant') }}:</span>
      <strong>{{ tenant?.name ?? '—' }}</strong>
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
          class="menu-item"
          :data-current="item.name === tenant?.name || undefined"
          @select="switchTo(item.name)"
        >
          <span>{{ item.name }}</span>
          <span v-if="item.friendly_name && item.friendly_name !== item.name" class="muted">{{ item.friendly_name }}</span>
          <span v-if="item.name === tenant?.name" class="visually-hidden">(current)</span>
        </DropdownMenuItem>
        <DropdownMenuSeparator class="menu-sep" />
        <DropdownMenuItem class="menu-item" @select="creating = true">+ {{ t('createTenant') }}</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenuPortal>
  </DropdownMenuRoot>
  <CreateTenantDialog v-model:open="creating" />
</template>

<style scoped>
.trigger {
  font: inherit;
  display: inline-flex;
  gap: 0.4rem;
  align-items: center;
  background: var(--surface-2);
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.3rem 0.7rem;
  cursor: pointer;
}
[data-current] {
  font-weight: 600;
}
</style>
