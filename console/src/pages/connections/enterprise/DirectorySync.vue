<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ApiError, type Connection, type SystemTenant } from '../../../api/client'
import type { DirectoryMappingItem, DirectoryProvisioning, SynchronizedGroup } from '../../../api/directory'
import { errorMessage, useServices } from '../../../context'
import Banner from '../../../ui/Banner.vue'
import Button from '../../../ui/Button.vue'
import Field from '../../../ui/Field.vue'
import ConfirmDialog from '../../../ui/ConfirmDialog.vue'
// Google Workspace directory provisioning (Plan 37c Phase C): configuration,
// administrator consent link, synchronization status, mapping and groups.
const props = defineProps<{ tenant: SystemTenant; connection: Connection }>(),
  { t } = useI18n(),
  { api } = useServices()
const config = ref<DirectoryProvisioning | null>(null),
  mapping = ref<DirectoryMappingItem[]>([]),
  automatic = ref(false),
  groupsMode = ref<'off' | 'all' | 'selected'>('off'),
  groups = ref<SynchronizedGroup[]>([]),
  groupIDs = ref(''),
  consent = ref(''),
  loading = ref(true),
  busy = ref(false),
  error = ref(''),
  status = ref(''),
  disableOpen = ref(false)
const locked = computed(() => busy.value || !!props.tenant.seeded)
let generation = 0
function show(c: DirectoryProvisioning | null) {
  config.value = c
  mapping.value = (c?.mapping ?? []).map((m) => ({ ...m }))
  automatic.value = !!c?.synchronize_automatically
  groupsMode.value = (c?.synchronize_groups as 'off' | 'all' | 'selected') ?? 'off'
}
async function load() {
  const mine = ++generation,
    tn = props.tenant,
    id = props.connection.id!
  loading.value = true
  error.value = ''
  consent.value = ''
  try {
    let c: DirectoryProvisioning | null = null
    try {
      c = await api.getDirectoryProvisioning(tn, id)
    } catch (e) {
      if (!(e instanceof ApiError && e.status === 404)) throw e
    }
    const gs = c ? (await api.listSynchronizedGroups(tn, id)).groups : []
    if (mine !== generation) return
    show(c)
    groups.value = gs
    groupIDs.value = gs.map((g) => g.id).join('\n')
  } catch (e) {
    if (mine === generation) error.value = errorMessage(e)
  } finally {
    if (mine === generation) loading.value = false
  }
}
watch(() => [props.tenant.name, props.connection.id], load, { immediate: true })
onBeforeUnmount(() => {
  generation++
})
async function run(fn: () => Promise<void>) {
  if (locked.value) return
  const mine = generation
  busy.value = true
  error.value = ''
  status.value = ''
  try {
    await fn()
  } catch (e) {
    if (mine === generation) error.value = errorMessage(e)
  } finally {
    if (mine === generation) busy.value = false
  }
}
const enable = () => run(async () => show(await api.createDirectoryProvisioning(props.tenant, props.connection.id!)))
const save = () =>
  run(async () => {
    show(
      await api.updateDirectoryProvisioning(props.tenant, props.connection.id!, {
        mapping: mapping.value,
        synchronize_automatically: automatic.value,
        synchronize_groups: groupsMode.value,
      }),
    )
    if (groupsMode.value === 'selected') {
      const ids = [...new Set(groupIDs.value.split(/[\s,]+/).filter(Boolean))]
      await api.replaceSynchronizedGroups(props.tenant, props.connection.id!, ids.map((id) => groups.value.find((g) => g.id === id) ?? { id }))
      groups.value = (await api.listSynchronizedGroups(props.tenant, props.connection.id!)).groups
    }
    status.value = t('saved')
  })
const resetMapping = () =>
  run(async () => {
    mapping.value = ((await api.getDirectoryDefaultMapping(props.tenant, props.connection.id!)).mapping ?? []).map((m) => ({ ...m }))
  })
const authorize = () => run(async () => void (consent.value = (await api.directoryConsentLink(props.tenant, props.connection.id!)).url))
const synchronize = () =>
  run(async () => {
    await api.synchronizeDirectory(props.tenant, props.connection.id!)
    status.value = t('dirsync.requested')
  })
const disable = () =>
  run(async () => {
    await api.deleteDirectoryProvisioning(props.tenant, props.connection.id!)
    disableOpen.value = false
    show(null)
  })
const callback = computed(() => 'https://' + props.tenant.host + '/directory-provisioning/callback')
</script>
<template>
  <section class="stack" :aria-label="t('dirsync.title')">
    <p>{{ t('dirsync.intro') }}</p>
    <Banner v-if="error" kind="error">{{ error }}</Banner>
    <p v-if="loading" role="status">{{ t('loading') }}</p>
    <template v-else-if="!config">
      <p class="card empty">{{ t('dirsync.disabled') }}</p>
      <div><Button data-testid="dirsync-enable" variant="primary" :disabled="locked" @click="enable">{{ t('dirsync.enable') }}</Button></div>
    </template>
    <template v-else>
      <section class="card stack" data-testid="dirsync-status">
        <h3>{{ t('dirsync.status') }}</h3>
        <dl class="m-0">
          <dt>{{ t('dirsync.lastAt') }}</dt>
          <dd>{{ config.last_synchronization_at ?? t('dirsync.never') }}</dd>
          <template v-if="config.last_synchronization_status">
            <dt>{{ t('dirsync.lastStatus') }}</dt>
            <dd>{{ config.last_synchronization_status }}</dd>
          </template>
          <template v-if="config.last_synchronization_error">
            <dt>{{ t('dirsync.lastError') }}</dt>
            <dd>{{ config.last_synchronization_error }}</dd>
          </template>
        </dl>
        <p class="muted">{{ t('dirsync.consentHint', { callback }) }}</p>
        <Banner v-if="consent" kind="info"
          >{{ t('dirsync.consentOnce') }} <a :href="consent" target="_blank" rel="noopener noreferrer" data-testid="dirsync-consent">{{ t('dirsync.consentOpen') }}</a></Banner
        >
        <div class="row">
          <Button data-testid="dirsync-authorize" :disabled="locked" @click="authorize">{{ t('dirsync.authorize') }}</Button
          ><Button data-testid="dirsync-sync" :disabled="locked" @click="synchronize">{{ t('dirsync.synchronize') }}</Button>
        </div>
      </section>
      <form class="card stack" @submit.prevent="save">
        <label class="check"><input v-model="automatic" type="checkbox" /> {{ t('dirsync.automatic') }}</label>
        <Field id="dirsync-groups" :label="t('dirsync.groups')"
          ><select id="dirsync-groups" v-model="groupsMode">
            <option value="off">{{ t('dirsync.groupsOff') }}</option>
            <option value="all">{{ t('dirsync.groupsAll') }}</option>
            <option value="selected">{{ t('dirsync.groupsSelected') }}</option>
          </select></Field
        >
        <Field v-if="groupsMode === 'selected'" id="dirsync-group-ids" :label="t('dirsync.groupIDs')"
          ><textarea id="dirsync-group-ids" v-model="groupIDs" rows="4" spellcheck="false"
        /></Field>
        <h3>{{ t('scim.mapping') }}</h3>
        <div v-for="(m, i) in mapping" :key="i" class="row">
          <Field :id="'dirsync-auth0-' + i" :label="t('scim.auth0')"><input :id="'dirsync-auth0-' + i" v-model="m.auth0" required maxlength="256" /></Field
          ><Field :id="'dirsync-idp-' + i" :label="t('dirsync.idpAttr')"><input :id="'dirsync-idp-' + i" v-model="m.idp" required maxlength="256" /></Field
          ><Button :disabled="locked" @click="mapping.splice(i, 1)">{{ t('scim.removeMapping') }}</Button>
        </div>
        <div class="row">
          <Button :disabled="locked || mapping.length >= 100" @click="mapping.push({ auth0: '', idp: '' })">{{ t('scim.addMapping') }}</Button
          ><Button :disabled="locked" @click="resetMapping">{{ t('scim.resetMapping') }}</Button><span class="flex-1" /><Button
            type="submit"
            variant="primary"
            :disabled="locked"
            >{{ t('dirsync.save') }}</Button
          ><span role="status">{{ status }}</span>
        </div>
      </form>
      <section class="card stack">
        <Button variant="danger" :disabled="locked" @click="disableOpen = true">{{ t('dirsync.disable') }}</Button>
      </section>
    </template>
    <ConfirmDialog
      v-model:open="disableOpen"
      :title="t('dirsync.disableTitle')"
      :description="t('dirsync.disableHint')"
      :confirm-label="t('dirsync.disable')"
      :busy="busy"
      :error="error"
      @confirm="disable"
    />
  </section>
</template>
