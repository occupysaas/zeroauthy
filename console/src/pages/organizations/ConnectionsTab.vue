<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Connection, OrganizationEnabledConnection, OrganizationEnabledConnectionUpdate, SystemTenant } from '../../api/client'
import { useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import Pager from '../roles/Pager.vue'
import { enterpriseStrategies } from '../connections/social/social'
import { usePanel } from './context'
const props = defineProps<{ tenant: SystemTenant; organizationId: string }>(), { t } = useI18n(), { api } = useServices()
const entries = ref<OrganizationEnabledConnection[]>([]), connections = ref<Connection[]>([]), page = ref(0), total = ref(0), selected = ref('')
const { loading, busy, error, reloadRequired, load, change } = usePanel(() => [props.tenant.host, props.organizationId], async () => {
  const tn = props.tenant, id = props.organizationId
  // The frozen limit is 50: read all enabled IDs so the picker also excludes other pages.
  return Promise.all([api.listOrganizationConnections(tn, id, 0, 50), api.allConnections(tn)])
}, ([result, available]) => { entries.value = result.enabled_connections; total.value = result.total; connections.value = available }, () => { entries.value = []; connections.value = []; page.value = 0; selected.value = '' })
function goto(next: number) { page.value = next; void load() }
const enterprise = (strategy: string) => (enterpriseStrategies as readonly string[]).includes(strategy)
function update(entry: OrganizationEnabledConnection, flag: keyof OrganizationEnabledConnectionUpdate, event: Event) {
  const value = (event.target as HTMLInputElement).checked, body = { [flag]: value }
  if (flag === 'assign_membership_on_login' && !value && entry.connection.strategy === 'auth0') body.is_signup_enabled = false
  void change(() => api.changeOrganizationConnection(props.tenant, props.organizationId, 'PATCH', entry.connection_id, body))
}
function enable() {
  if (!selected.value || total.value >= 50) return
  void change(() => api.changeOrganizationConnection(props.tenant, props.organizationId, 'POST', selected.value), async () => { selected.value = ''; await load() })
}
</script>
<template>
  <div class="stack"><p>{{ t('orgs.connectionLimit') }}</p><Banner v-if="error" kind="error">{{ error }} <Button :disabled="busy" @click="load">{{ t('retry') }}</Button></Banner><Banner v-if="reloadRequired" kind="error">{{ t('orgs.uncertain') }}</Banner>
    <form class="card row" @submit.prevent="enable"><Field id="organization-connection" :label="t('orgs.selectConnection')"><select id="organization-connection" v-model="selected"><option value="" disabled>{{ t('orgs.selectConnection') }}</option><option v-for="c in connections.filter(c => !entries.some(e => e.connection_id === c.id))" :key="c.id" :value="c.id">{{ c.name }}</option></select></Field><Button type="submit" :disabled="busy || reloadRequired || !selected || total >= 50">{{ t('orgs.enable') }}</Button></form>
    <p v-if="loading" role="status">{{ t('loading') }}</p><template v-else><p v-if="!entries.length">{{ t('orgs.noConnections') }}</p>
      <section v-for="entry in entries.slice(page * 20, (page + 1) * 20)" :key="entry.connection_id" class="card stack" :data-connection="entry.connection_id"><h3>{{ entry.connection.name }}</h3><code>{{ entry.connection.strategy }}</code>
        <label><input type="checkbox" data-flag="assign_membership_on_login" :checked="entry.assign_membership_on_login" :disabled="busy || reloadRequired" @change="update(entry, 'assign_membership_on_login', $event)" /> {{ t('orgs.autoMembership') }}</label>
        <label><input type="checkbox" data-flag="is_signup_enabled" :checked="entry.is_signup_enabled" :disabled="busy || reloadRequired || entry.connection.strategy !== 'auth0' || !entry.assign_membership_on_login" @change="update(entry, 'is_signup_enabled', $event)" /> {{ t('orgs.signup') }}</label>
        <label><input type="checkbox" data-flag="show_as_button" :checked="entry.show_as_button" :disabled="busy || reloadRequired || !enterprise(entry.connection.strategy)" @change="update(entry, 'show_as_button', $event)" /> {{ t('orgs.button') }}</label>
        <Button variant="danger" :disabled="busy || reloadRequired" @click="change(() => api.changeOrganizationConnection(props.tenant, props.organizationId, 'DELETE', entry.connection_id))">{{ t('orgs.disable') }}</Button>
      </section><Pager :page="page" :total="total" :busy="busy" @change="goto" />
    </template>
  </div>
</template>
