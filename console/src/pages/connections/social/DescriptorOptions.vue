<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { descriptorScope, type SocialDescriptor } from './social'

// The scope controls of every Plan 39b descriptor strategy, shared by the
// create and settings forms. The effective scope is derived, never typed.
const { t } = useI18n()
const props = defineProps<{ descriptor: SocialDescriptor; communityError?: string; freeformError?: string }>()
const flags = defineModel<Record<string, boolean>>('flags', { required: true })
const freeform = defineModel<string>('freeform', { required: true })
const community = defineModel<string>('community', { default: '' })
const protocol = defineModel<string>('protocol', { default: 'oauth2' })
const oauth1 = computed(() => props.descriptor.fields.includes('protocol') && protocol.value === 'oauth1')
const effective = computed(() => descriptorScope(props.descriptor, flags.value, freeform.value, protocol.value))

function toggle(option: string, on: boolean) {
  flags.value = { ...flags.value, [option]: on }
}
</script>

<template>
  <div class="stack" data-testid="descriptor-options">
    <p v-if="descriptor.fields.includes('login_hint')" class="muted" data-testid="descriptor-login-hint">{{ t('social.shopifyLoginHint') }}</p>
    <div v-if="descriptor.fields.includes('protocol')" class="grid gap-1">
      <label for="descriptor-protocol" class="font-bold">{{ t('social.twitterProtocol') }}</label>
      <select id="descriptor-protocol" v-model="protocol">
        <option value="oauth2">OAuth 2.0</option>
        <option value="oauth1">OAuth 1.0a</option>
      </select>
    </div>
    <div v-if="descriptor.fields.includes('community_base_url')" class="grid gap-1">
      <label for="descriptor-community" class="font-bold">{{ t('social.communityBaseURL') }}</label>
      <input id="descriptor-community" v-model="community" type="url" maxlength="2048" autocomplete="off" spellcheck="false" :aria-invalid="!!communityError" :aria-describedby="communityError ? 'descriptor-community-error' : undefined" />
      <p v-if="communityError" id="descriptor-community-error" class="m-0 text-sm text-danger">{{ communityError }}</p>
    </div>
    <fieldset v-if="!oauth1 && descriptor.flags.length" class="stack m-0 min-w-0 border-0 p-0">
      <legend class="p-0 font-bold">{{ t('social.descriptorScopes') }}</legend>
      <label v-for="f in descriptor.flags" :key="f.option" class="check">
        <input :id="`descriptor-flag-${f.option}`" type="checkbox" :checked="flags[f.option] === true" @change="toggle(f.option, ($event.target as HTMLInputElement).checked)" />
        <span class="break-all">{{ f.scopes.join(' ') }}</span>
      </label>
    </fieldset>
    <div v-if="!oauth1 && descriptor.freeform_scopes" class="grid gap-1">
      <label for="descriptor-freeform" class="font-bold">{{ t('social.freeformScopes') }}</label>
      <input id="descriptor-freeform" v-model="freeform" type="text" autocomplete="off" spellcheck="false" :aria-invalid="!!freeformError" aria-describedby="descriptor-freeform-hint" />
      <p id="descriptor-freeform-hint" class="m-0 text-sm text-muted">{{ freeformError || t('social.freeformScopesHint') }}</p>
    </div>
    <div v-if="!oauth1" class="grid gap-1">
      <label for="descriptor-effective" class="font-bold">{{ t('social.githubEffective') }}</label>
      <input id="descriptor-effective" :value="effective" type="text" readonly />
    </div>
  </div>
</template>
