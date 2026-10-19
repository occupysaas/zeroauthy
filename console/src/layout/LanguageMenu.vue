<script setup lang="ts">
import {
  DropdownMenuContent,
  DropdownMenuPortal,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuRoot,
  DropdownMenuTrigger,
} from 'reka-ui'
import { storeToRefs } from 'pinia'
import { useI18n } from 'vue-i18n'
import { locales, type Locale } from '../i18n'
import { usePreferencesStore } from '../stores/preferences'
import GlobeIcon from '../ui/GlobeIcon.vue'

const { t } = useI18n()
const prefs = usePreferencesStore()
const { locale } = storeToRefs(prefs)
</script>

<template>
  <DropdownMenuRoot>
    <DropdownMenuTrigger class="trigger" :aria-label="t('language')">
      <GlobeIcon aria-hidden="true" />
    </DropdownMenuTrigger>
    <DropdownMenuPortal>
      <DropdownMenuContent class="menu" align="end" :side-offset="6">
        <DropdownMenuRadioGroup :model-value="locale" @update:model-value="prefs.setLocale($event as Locale)">
          <DropdownMenuRadioItem v-for="l in locales" :key="l.code" class="menu-item" :value="l.code">{{ l.name }}</DropdownMenuRadioItem>
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenuPortal>
  </DropdownMenuRoot>
</template>

<style scoped>
.trigger {
  display: inline-flex;
  align-items: center;
  background: transparent;
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.3rem 0.5rem;
  cursor: pointer;
}
.menu-item[data-state='checked']::before {
  content: '✓';
}
</style>
