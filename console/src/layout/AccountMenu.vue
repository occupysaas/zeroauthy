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
import { ref, watch } from 'vue'
import { useServices } from '../context'
import { t } from '../strings'
import { applyTheme, savedTheme, type Theme } from '../theme'

const { auth } = useServices()
const theme = ref<Theme>(savedTheme())
watch(theme, applyTheme)
</script>

<template>
  <DropdownMenuRoot>
    <DropdownMenuTrigger class="trigger" :aria-label="t.account">
      {{ auth.user.email || t.account }} <span aria-hidden="true">▾</span>
    </DropdownMenuTrigger>
    <DropdownMenuPortal>
      <DropdownMenuContent class="menu" align="end" :side-offset="6">
        <DropdownMenuLabel class="menu-label">{{ auth.user.email }}</DropdownMenuLabel>
        <DropdownMenuSeparator class="menu-sep" />
        <DropdownMenuRadioGroup v-model="theme">
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
