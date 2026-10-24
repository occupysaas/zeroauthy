<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ApiError, type SystemTenant, type User, type UserBlocks } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import ConfirmDialog from './ConfirmDialog.vue'
const props = defineProps<{ tenant: SystemTenant; user?: User }>()
const { t } = useI18n()
const { api } = useServices()
const rows = ref<UserBlocks['blocked_for']>([])
const ip = ref('')
const checkedIP = ref('')
const blocked = ref<boolean | null>(null)
const loading = ref(false)
const error = ref('')
const open = ref(false)
const busy = ref(false)
let generation = 0
async function load() {
  const tn = props.tenant
  const userId = props.user?.user_id
  const address = ip.value.trim()
  if (!userId && !address) return
  const mine = ++generation
  loading.value = true; error.value = ''; blocked.value = null; rows.value = []
  checkedIP.value = address
  try {
    if (userId) {
      const result = await api.getUserBlocks(tn, userId)
      if (mine === generation) rows.value = result.blocked_for
    } else {
      await api.getIPBlock(tn, address)
      if (mine === generation) blocked.value = true
    }
  } catch (e) {
    if (mine !== generation) return
    if (!userId && e instanceof ApiError && e.status === 404) blocked.value = false
    else error.value = errorMessage(e)
  } finally { if (mine === generation) loading.value = false }
}
watch(() => [props.tenant.name, props.tenant.host, props.user?.user_id], () => {
  generation++; rows.value = []; ip.value = ''; checkedIP.value = ''; blocked.value = null; open.value = false; error.value = ''; loading.value = false; busy.value = false
  if (props.user) void load()
}, { immediate: true })
watch(ip, () => { if (!props.user) { generation++; blocked.value = null; checkedIP.value = ''; loading.value = false; open.value = false } })
onBeforeUnmount(() => { generation++ })
async function clear() {
  const mine = generation
  const tn = props.tenant
  const userId = props.user?.user_id
  const address = checkedIP.value
  busy.value = true; error.value = ''
  try {
    if (userId) await api.deleteUserBlocks(tn, userId)
    else await api.deleteIPBlock(tn, address)
    if (mine !== generation) return
    open.value = false
    busy.value = false
    await load()
  } catch (e) { if (mine === generation) error.value = errorMessage(e) }
  finally { if (mine === generation) busy.value = false }
}
</script>
<template>
  <section class="stack max-w-2xl py-4">
    <h2>{{ t(user ? 'policy.loginBlocks' : 'policy.ipBlocks') }}</h2>
    <p class="muted">{{ t(user ? 'policy.blocksHint' : 'policy.ipBlocksHint') }}</p>
    <form v-if="!user" class="stack" @submit.prevent="load">
      <Field id="block-ip" :label="t('policy.ipAddress')"><input id="block-ip" v-model="ip" type="text" required /></Field>
      <div><Button type="submit" :disabled="loading || !ip.trim()">{{ t('policy.checkIP') }}</Button></div>
    </form>
    <Banner v-if="error && !open" kind="error">{{ error }} <Button @click="load">{{ t('retry') }}</Button></Banner>
    <p v-else-if="loading" role="status">{{ t('loading') }}</p>
    <template v-else-if="!error">
      <template v-if="user">
        <p v-if="!rows.length">{{ t('policy.noBlocks') }}</p>
        <ul v-else class="break-words"><li v-for="(row, i) in rows" :key="i">{{ row.identifier }} · {{ row.ip || t('policy.allIPs') }} · {{ row.connection }}</li></ul>
        <div class="row flex-wrap"><Button :disabled="!rows.length || busy" variant="danger" @click="open = true">{{ t('policy.clearBlocks') }}</Button><Button @click="load">{{ t('policy.refresh') }}</Button></div>
      </template>
      <template v-else-if="blocked !== null">
        <p role="status">{{ checkedIP }}: {{ t(blocked ? 'policy.ipBlocked' : 'policy.ipUnblocked') }}</p>
        <div><Button v-if="blocked" variant="danger" :disabled="busy" @click="open = true">{{ t('policy.clearIP') }}</Button></div>
      </template>
    </template>
    <ConfirmDialog v-model:open="open" :title="t(user ? 'policy.clearBlocks' : 'policy.clearIP')" :description="t(user ? 'policy.clearBlocksBody' : 'policy.clearIPBody', { ip: checkedIP })" :confirm-label="t(user ? 'policy.clearBlocks' : 'policy.clearIP')" :busy="busy" :error="error" @confirm="clear" />
  </section>
</template>
