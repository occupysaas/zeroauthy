<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { OrganizationClientAssociation, SystemTenant } from '../../api/client'
import { useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import { usePanel } from './context'
const props = defineProps<{ tenant: SystemTenant; organizationId: string }>(), { api } = useServices(), { t } = useI18n()
const entries = ref<OrganizationClientAssociation[]>([]), from = ref(''), next = ref(''), client = ref(''), memberAccess = ref(true), entitlement = ref(false)
const { loading, busy, error, reloadRequired, load, change } = usePanel(() => [props.tenant.host, props.organizationId], () => Promise.all([api.getOrganization(props.tenant, props.organizationId), api.listOrganizationClients(props.tenant, props.organizationId, from.value)]), ([org, r]) => { entitlement.value = org.is_app_entitlement_active; entries.value = r.clients; next.value = r.next ?? '' }, () => { entries.value = []; from.value = ''; next.value = ''; client.value = ''; memberAccess.value = true; entitlement.value = false })
const blocked = computed(() => loading.value || busy.value || !!error.value || reloadRequired.value)
function saveEntitlement() { const tn = props.tenant, id = props.organizationId, body = { is_app_entitlement_active: entitlement.value }; void change(() => api.updateOrganization(tn, id, body)) }
function associate() { if (!client.value.trim() || blocked.value) return; const tn = props.tenant, id = props.organizationId, cid = client.value.trim(), access = memberAccess.value; void change(() => api.associateOrganizationClient(tn, id, cid, access), async () => { client.value = ''; from.value = ''; await load() }) }
function update(clientId: string, value?: boolean) { const tn = props.tenant, id = props.organizationId; void change(() => value === undefined ? api.deleteOrganizationClient(tn, id, clientId) : api.updateOrganizationClient(tn, id, clientId, value)) }
function goto(cursor: string) { from.value = cursor; void load() }
</script>
<template>
 <div class="stack"><Banner v-if="error" kind="error">{{ error }} <Button :disabled="busy" @click="load">{{ t('retry') }}</Button></Banner><Banner v-if="reloadRequired" kind="error">{{ t('orgs.uncertain') }}</Banner>
 <section class="card stack"><label><input id="organization-entitlement" v-model="entitlement" type="checkbox" :disabled="blocked" /> {{ t('orgs.entitlement') }}</label><p>{{ t(entitlement ? 'orgs.entitlementOn' : 'orgs.entitlementOff') }}</p><Button :disabled="blocked" @click="saveEntitlement">{{ t('orgs.saveEntitlement') }}</Button></section>
 <form class="card stack" @submit.prevent="associate"><Field id="organization-client" :label="t('orgs.clientID')"><input id="organization-client" v-model="client" required /></Field><label><input v-model="memberAccess" type="checkbox" /> {{ t('orgs.memberAccess') }}</label><Button type="submit" :disabled="blocked || !client.trim()">{{ t('orgs.associateApplication') }}</Button></form>
 <p v-if="loading" role="status">{{ t('loading') }}</p><section v-for="entry in entries" :key="entry.client_id" class="card row"><span>{{ entry.client?.name }}</span><code>{{ entry.client_id }}</code><label><input type="checkbox" :checked="entry.use_for_member_access" :disabled="blocked" @change="update(entry.client_id, ($event.target as HTMLInputElement).checked)" /> {{ t('orgs.memberAccess') }}</label><Button variant="danger" :disabled="blocked" @click="update(entry.client_id)">{{ t('orgs.removeAssociation') }}</Button></section><div class="row"><Button :disabled="blocked || !from" @click="goto('')">{{ t('orgs.firstPage') }}</Button><Button :disabled="blocked || !next" @click="goto(next)">{{ t('next') }}</Button></div>
 </div>
</template>
