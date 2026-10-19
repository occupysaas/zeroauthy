<script setup lang="ts">
import {
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuPortal,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuRoot,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from 'reka-ui'
import { storeToRefs } from 'pinia'
import { useServices } from '../context'
import { t } from '../strings'
import type { Theme } from '../theme'
import { usePreferencesStore } from '../stores/preferences'
import { useSessionStore } from '../stores/session'

const { auth } = useServices()
const prefs = usePreferencesStore()
const session = useSessionStore()
const { theme } = storeToRefs(prefs)
</script>

<template>
  <DropdownMenuRoot>
    <DropdownMenuTrigger class="trigger" :aria-label="t.account">
      {{ session.email || t.account }} <span aria-hidden="true">▾</span>
    </DropdownMenuTrigger>
    <DropdownMenuPortal>
      <DropdownMenuContent class="menu" align="end" :side-offset="6">
        <DropdownMenuLabel class="menu-label">{{ session.email }}</DropdownMenuLabel>
        <DropdownMenuSeparator class="menu-sep" />
        <DropdownMenuRadioGroup :model-value="theme" @update:model-value="prefs.setTheme($event as Theme)">
          <DropdownMenuRadioItem class="menu-item" value="system">{{ t.themeSystem }}</DropdownMenuRadioItem>
          <DropdownMenuRadioItem class="menu-item" value="light">{{ t.themeLight }}</DropdownMenuRadioItem>
          <DropdownMenuRadioItem class="menu-item" value="dark">{{ t.themeDark }}</DropdownMenuRadioItem>
        </DropdownMenuRadioGroup>
        <DropdownMenuSeparator class="menu-sep" />
        <DropdownMenuItem class="menu-item" @select="auth.logout()">{{ t.signOut }}</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenuPortal>
  </DropdownMenuRoot>
</template>

<style scoped>
.trigger {
  font: inherit;
  background: transparent;
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.3rem 0.7rem;
  cursor: pointer;
}
.menu-item[data-state='checked']::before {
  content: '✓';
}
</style>
