<script setup lang="ts">
import { reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { SystemTenant, User, UserUpdate } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import { formatTime } from './policy'

const { t, locale } = useI18n()
const props = defineProps<{ tenant: SystemTenant; user: User }>()
const emit = defineEmits<{ saved: [User] }>()
const { api } = useServices()

// The profile fields this tab edits. Email and password have their own
// actions: the server refuses them together.
const FIELDS = ['name', 'given_name', 'family_name', 'nickname', 'picture'] as const
type Field_ = (typeof FIELDS)[number]
const form = reactive<Record<Field_, string>>({ name: '', given_name: '', family_name: '', nickname: '', picture: '' })
const error = ref('')
const status = ref('')
const busy = ref(false)

function reset() {
  for (const f of FIELDS) form[f] = props.user[f] ?? ''
}
watch(() => props.user, reset, { immediate: true })

async function save() {
  const body: UserUpdate = {}
  for (const f of FIELDS) if (form[f] !== (props.user[f] ?? '')) body[f] = form[f]
  error.value = ''
  status.value = ''
  if (Object.keys(body).length === 0) {
    status.value = t('userd.noChanges')
    return
  }
  busy.value = true
  try {
    emit('saved', await api.updateUser(props.tenant, props.user.user_id ?? '', body))
    status.value = t('saved')
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="stack">
    <dl class="m-0 grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1">
      <dt class="muted">{{ t('userd.userId') }}</dt>
      <dd class="m-0"><code>{{ user.user_id }}</code></dd>
      <dt class="muted">{{ t('users.email') }}</dt>
      <dd class="m-0">
        <template v-if="user.email">{{ user.email }} <span class="muted">({{ user.email_verified ? t('userd.verified') : t('userd.unverified') }})</span></template>
        <span v-else class="muted">{{ t('userd.none') }}</span>
      </dd>
      <dt v-if="user.username" class="muted">{{ t('users.username') }}</dt>
      <dd v-if="user.username" class="m-0">{{ user.username }}</dd>
      <dt class="muted">{{ t('userd.created') }}</dt>
      <dd class="m-0">{{ user.created_at ? formatTime(user.created_at, locale) : '' }}</dd>
      <dt class="muted">{{ t('users.lastLogin') }}</dt>
      <dd class="m-0">{{ user.last_login ? formatTime(user.last_login, locale) : t('users.never') }}</dd>
      <dt class="muted">{{ t('users.logins') }}</dt>
      <dd class="m-0">{{ user.logins_count ?? 0 }}</dd>
      <dt class="muted">{{ t('userd.phone') }}</dt>
      <dd class="m-0" data-testid="phone">
        <template v-if="user.phone_number">{{ user.phone_number }} <span class="muted">({{ t('userd.phoneStored') }})</span></template>
        <span v-else class="muted">{{ t('userd.none') }}</span>
      </dd>
    </dl>

    <form id="user-profile" class="stack card" novalidate @submit.prevent="save">
      <Banner v-if="error" kind="error">{{ error }}</Banner>
      <Field id="user-name" :label="t('userd.name')"><input id="user-name" v-model="form.name" type="text" autocomplete="off" /></Field>
      <Field id="user-given_name" :label="t('userd.givenName')"><input id="user-given_name" v-model="form.given_name" type="text" autocomplete="off" /></Field>
      <Field id="user-family_name" :label="t('userd.familyName')"><input id="user-family_name" v-model="form.family_name" type="text" autocomplete="off" /></Field>
      <Field id="user-nickname" :label="t('userd.nickname')"><input id="user-nickname" v-model="form.nickname" type="text" autocomplete="off" /></Field>
      <Field id="user-picture" :label="t('userd.picture')"><input id="user-picture" v-model="form.picture" type="text" autocomplete="off" spellcheck="false" /></Field>
      <div class="row">
        <Button variant="primary" type="submit" :disabled="busy">{{ t('userd.saveProfile') }}</Button>
        <span class="muted" role="status">{{ status }}</span>
      </div>
    </form>
  </div>
</template>
