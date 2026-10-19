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
import { useI18n } from 'vue-i18n'
import type { Theme } from '../theme'
import { usePreferencesStore } from '../stores/preferences'
import { useSessionStore } from '../stores/session'

const { t } = useI18n()

const { auth } = useServices()
const prefs = usePreferencesStore()
const session = useSessionStore()
const { theme } = storeToRefs(prefs)
</script>

<template>
  <DropdownMenuRoot>
    <DropdownMenuTrigger class="cursor-pointer rounded border border-transparent bg-header-chip px-3 py-1 font-sans text-header-text hover:border-header-text" :aria-label="t('account')">
      {{ session.email || t('account') }} <span aria-hidden="true">▾</span>
    </DropdownMenuTrigger>
    <DropdownMenuPortal>
      <DropdownMenuContent class="menu" align="end" :side-offset="6">
        <DropdownMenuLabel class="menu-label">{{ session.email }}</DropdownMenuLabel>
        <DropdownMenuSeparator class="menu-sep" />
        <DropdownMenuRadioGroup :model-value="theme" @update:model-value="prefs.setTheme($event as Theme)">
          <DropdownMenuRadioItem class="menu-item" value="system">{{ t('themeSystem') }}</DropdownMenuRadioItem>
          <DropdownMenuRadioItem class="menu-item" value="light">{{ t('themeLight') }}</DropdownMenuRadioItem>
          <DropdownMenuRadioItem class="menu-item" value="dark">{{ t('themeDark') }}</DropdownMenuRadioItem>
        </DropdownMenuRadioGroup>
        <DropdownMenuSeparator class="menu-sep" />
        <DropdownMenuItem class="menu-item" @select="auth.logout()">{{ t('signOut') }}</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenuPortal>
  </DropdownMenuRoot>
</template>
