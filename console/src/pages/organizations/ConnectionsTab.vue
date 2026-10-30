<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { ApiError, type Connection, type OrganizationConnection, type OrganizationConnectionUpdate, type SystemTenant } from '../../api/client'
import { useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import Pager from '../roles/Pager.vue'
import { enterpriseStrategies } from '../connections/social/social'
import { usePanel } from './context'
const props = defineProps<{ tenant: SystemTenant; organizationId: string }>(), { t } = useI18n(), { api } = useServices()
const extended = ref(true)
const entries = ref<OrganizationConnection[]>([]), connections = ref<Connection[]>([]), page = ref(0), total = ref(0), selected = ref('')
const { loading, busy, error, reloadRequired, load, change } = usePanel(() => [props.tenant.host, props.organizationId], async () => {
  const tn = props.tenant, id = props.organizationId
  // The frozen limit is 50: read all enabled IDs so the picker also excludes other pages.
  return Promise.all([api.listAllOrganizationConnections(tn, id).then(result => ({ entries: result.connections, total: result.total, extended: true })).catch(async e => {
    if (!(e instanceof ApiError) || e.status !== 501 || e.errorCode !== 'organizations_ii_unavailable') throw e
    const result = await api.listOrganizationConnections(tn, id, 0, 50)
    return { entries: result.enabled_connections, total: result.total, extended: false }
  }), api.allConnections(tn)])
}, ([result, available]) => { entries.value = result.entries; extended.value = result.extended; total.value = result.total; connections.value = available }, () => { entries.value = []; connections.value = []; page.value = 0; selected.value = ''; extended.value = true })
const blocked = computed(() => loading.value || busy.value || !!error.value || reloadRequired.value)
function goto(next: number) { page.value = next; void load() }
const delegationFields = [{ key: 'organization_access_level' as const, label: 'orgs.organization_access_level' }, { key: 'organization_member_access_level' as const, label: 'orgs.organization_member_access_level' }]
const delegationLevels = [{ value: 'none', label: 'orgs.level_none' }, { value: 'readonly', label: 'orgs.level_readonly' }, { value: 'limited', label: 'orgs.level_limited' }, { value: 'full', label: 'orgs.level_full' }]
const enterprise = (strategy: string) => (enterpriseStrategies as readonly string[]).includes(strategy)
function update(entry: OrganizationConnection, flag: keyof OrganizationConnectionUpdate, event: Event) {
  const value = (event.target as HTMLInputElement).checked, body = { [flag]: value }
  if (flag === 'assign_membership_on_login' && !value && entry.connection?.strategy === 'auth0') body.is_signup_enabled = false
  const tn = props.tenant, id = props.organizationId
  void change(() => extended.value ? api.changeAllOrganizationConnection(tn, id, entry.connection_id!, 'PATCH', body) : api.changeOrganizationConnection(tn, id, 'PATCH', entry.connection_id!, body))
}
function enable() {
  if (!selected.value || total.value >= 50) return
  const tn = props.tenant, id = props.organizationId, cid = selected.value
  void change(() => extended.value ? api.changeAllOrganizationConnection(tn, id, cid, 'POST') : api.changeOrganizationConnection(tn, id, 'POST', cid), async () => { selected.value = ''; await load() })
}
function save(entry: OrganizationConnection) {
  if (!extended.value || !entry.connection_id || blocked.value) return
  const tn = props.tenant, id = props.organizationId, cid = entry.connection_id
  const body = { organization_connection_name: entry.organization_connection_name, organization_access_level: entry.organization_access_level, organization_member_access_level: entry.organization_member_access_level }
  void change(() => api.changeAllOrganizationConnection(tn, id, cid, 'PATCH', body))
}
function remove(entry: OrganizationConnection) {
  if (!entry.connection_id || blocked.value) return
  const tn = props.tenant, id = props.organizationId, cid = entry.connection_id
  void change(() => extended.value ? api.changeAllOrganizationConnection(tn, id, cid, 'DELETE') : api.changeOrganizationConnection(tn, id, 'DELETE', cid))
}
</script>
<template>
  <div class="stack"><p>{{ t('orgs.connectionLimit') }}</p><Banner v-if="error" kind="error">{{ error }} <Button :disabled="busy" @click="load">{{ t('retry') }}</Button></Banner><Banner v-if="reloadRequired" kind="error">{{ t('orgs.uncertain') }}</Banner>
    <form class="card row" @submit.prevent="enable"><Field id="organization-connection" :label="t('orgs.selectConnection')"><select id="organization-connection" v-model="selected"><option value="" disabled>{{ t('orgs.selectConnection') }}</option><option v-for="c in connections.filter(c => !entries.some(e => e.connection_id === c.id))" :key="c.id" :value="c.id">{{ c.name }}</option></select></Field><Button type="submit" :disabled="blocked || !selected || total >= 50">{{ t('orgs.enable') }}</Button></form>
    <p v-if="loading" role="status">{{ t('loading') }}</p><template v-else><p v-if="!entries.length">{{ t('orgs.noConnections') }}</p>
      <section v-for="entry in entries.slice(page * 20, (page + 1) * 20)" :key="entry.connection_id" class="card stack" :data-connection="entry.connection_id"><h3>{{ entry.organization_connection_name || entry.connection?.name }}</h3><code>{{ entry.connection?.strategy }}</code>
        <template v-if="extended"><label><input type="checkbox" data-flag="is_enabled" :checked="entry.is_enabled !== false" :disabled="blocked" @change="update(entry, 'is_enabled', $event)" /> {{ t('orgs.connectionEnabled') }}</label>
        <Field :id="'connection-name-' + entry.connection_id" :label="t('orgs.localConnectionName')"><input :id="'connection-name-' + entry.connection_id" v-model="entry.organization_connection_name" maxlength="50" /></Field><p>{{ t('orgs.delegationHint') }}</p>
        <Field v-for="field in delegationFields" :id="field.key + entry.connection_id" :key="field.key" :label="t(field.label)"><select :id="field.key + entry.connection_id" v-model="entry[field.key]" :disabled="blocked"><option v-for="level in delegationLevels" :key="level.value" :value="level.value">{{ t(level.label) }}</option></select></Field><Button :disabled="blocked" @click="save(entry)">{{ t('save') }}</Button></template><p v-else>{{ t('orgs.legacyConnections') }}</p>
        <label><input type="checkbox" data-flag="assign_membership_on_login" :checked="entry.assign_membership_on_login" :disabled="blocked" @change="update(entry, 'assign_membership_on_login', $event)" /> {{ t('orgs.autoMembership') }}</label>
        <label><input type="checkbox" data-flag="is_signup_enabled" :checked="entry.is_signup_enabled" :disabled="blocked || entry.connection?.strategy !== 'auth0' || !entry.assign_membership_on_login" @change="update(entry, 'is_signup_enabled', $event)" /> {{ t('orgs.signup') }}</label>
        <label><input type="checkbox" data-flag="show_as_button" :checked="entry.show_as_button" :disabled="blocked || !enterprise(entry.connection?.strategy ?? '')" @change="update(entry, 'show_as_button', $event)" /> {{ t('orgs.button') }}</label>
        <Button variant="danger" :disabled="blocked" @click="remove(entry)">{{ t('orgs.disable') }}</Button>
      </section><Pager :page="page" :total="total" :busy="busy" @change="goto" />
    </template>
  </div>
</template>
