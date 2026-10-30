<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { OrganizationClientGrant, SystemTenant } from '../../api/client'
import { useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import Pager from '../roles/Pager.vue'
import { usePanel } from './context'
const props = defineProps<{ tenant: SystemTenant; organizationId: string }>(), { api } = useServices(), { t } = useI18n()
const entries = ref<OrganizationClientGrant[]>([]), grant = ref(''), page = ref(0), total = ref(0)
const { loading, busy, error, reloadRequired, load, change } = usePanel(() => [props.tenant.host, props.organizationId], () => api.listOrganizationGrants(props.tenant, props.organizationId, page.value), r => { entries.value = r.client_grants; total.value = r.total }, () => { entries.value = []; grant.value = ''; page.value = 0; total.value = 0 })
const blocked = computed(() => loading.value || busy.value || !!error.value || reloadRequired.value)
function associate() { if (blocked.value || !grant.value.trim()) return; const tn = props.tenant, id = props.organizationId, gid = grant.value.trim(); void change(() => api.changeOrganizationGrant(tn, id, gid, 'POST'), async () => { grant.value = ''; await load() }) }
function remove(entry: OrganizationClientGrant) { if (!entry.id) return; const tn = props.tenant, id = props.organizationId, gid = entry.id; void change(() => api.changeOrganizationGrant(tn, id, gid, 'DELETE')) }
function save(entry: OrganizationClientGrant) { if (!entry.id || blocked.value) return; const tn = props.tenant, id = entry.id, body = { organization_usage: entry.organization_usage as 'deny' | 'allow' | 'require', allow_any_organization: !!entry.allow_any_organization }; void change(() => api.updateClientGrant(tn, id, body)) }
function goto(next: number) { page.value = next; void load() }
</script>
<template>
 <div class="stack"><Banner v-if="error" kind="error">{{ error }} <Button :disabled="busy" @click="load">{{ t('retry') }}</Button></Banner><Banner v-if="reloadRequired" kind="error">{{ t('orgs.uncertain') }}</Banner><p>{{ t('orgs.grantHint') }}</p>
 <form class="card row" @submit.prevent="associate"><Field id="organization-grant" :label="t('orgs.grantID')"><input id="organization-grant" v-model="grant" required /></Field><Button type="submit" :disabled="blocked || !grant.trim()">{{ t('orgs.associateGrant') }}</Button></form>
 <p v-if="loading" role="status">{{ t('loading') }}</p><section v-for="entry in entries" :key="entry.id" class="card stack" :data-grant="entry.id"><code>{{ entry.id }} — {{ entry.client_id }}</code><p>{{ entry.audience }}</p><p>{{ t('orgs.grantScopes') }} {{ entry.scope?.join(', ') }}</p><Field :id="'grant-usage-' + entry.id" :label="t('orgs.usage')"><select :id="'grant-usage-' + entry.id" v-model="entry.organization_usage" :disabled="blocked"><option value="deny">{{ t('orgs.deny') }}</option><option value="allow">{{ t('orgs.allowUsage') }}</option><option value="require">{{ t('orgs.require') }}</option></select></Field><label><input v-model="entry.allow_any_organization" type="checkbox" :disabled="blocked" /> {{ t('orgs.anyOrganization') }}</label><p>{{ t('orgs.grantPolicyHint') }}</p><div class="row"><Button :disabled="blocked" @click="save(entry)">{{ t('orgs.savePolicy') }}</Button><Button variant="danger" :disabled="blocked" @click="remove(entry)">{{ t('orgs.removeAssociation') }}</Button></div></section><Pager :page="page" :total="total" :busy="blocked" @change="goto" />
 </div>
</template>
