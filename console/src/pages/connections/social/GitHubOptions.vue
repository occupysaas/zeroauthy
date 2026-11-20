<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { githubScope, githubScopeFlags } from './social'

// The GitHub scope controls shared by the create and settings forms. The
// effective scope is derived, never typed: it is shown read-only.
const { t } = useI18n()
const email = defineModel<boolean>('email', { required: true })
const flags = defineModel<Record<string, boolean>>('flags', { required: true })
const effective = computed(() => githubScope(email.value, flags.value))

function toggle(option: string, on: boolean) {
  flags.value = { ...flags.value, [option]: on }
}
</script>

<template>
  <div class="stack" data-testid="github-options">
    <p class="muted">{{ t('social.githubAppNote') }}</p>
    <label class="check"><input id="github-email" v-model="email" type="checkbox" /> <span>{{ t('social.githubEmail') }}</span></label>
    <fieldset class="stack m-0 min-w-0 border-0 p-0">
      <legend class="p-0 font-bold">{{ t('social.githubScopes') }}</legend>
      <p class="muted">{{ t('social.githubScopesHint') }}</p>
      <label v-for="f in githubScopeFlags" :key="f.option" class="check">
        <input :id="`github-scope-${f.option}`" type="checkbox" :checked="flags[f.option] === true" @change="toggle(f.option, ($event.target as HTMLInputElement).checked)" />
        <span class="break-all">{{ f.scope }}</span>
      </label>
    </fieldset>
    <div class="grid gap-1">
      <label for="github-effective" class="font-bold">{{ t('social.githubEffective') }}</label>
      <input id="github-effective" :value="effective" type="text" readonly aria-describedby="github-effective-hint" />
      <p id="github-effective-hint" class="m-0 text-sm text-muted">{{ t('social.githubEffectiveHint') }}</p>
    </div>
  </div>
</template>
