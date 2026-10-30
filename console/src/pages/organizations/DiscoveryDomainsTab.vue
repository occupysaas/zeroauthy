<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { OrganizationDiscoveryDomain, SystemTenant } from '../../api/client'
import { useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import Modal from '../../ui/Modal.vue'
import { usePanel } from './context'
const props = defineProps<{ tenant: SystemTenant; organizationId: string }>(), { api } = useServices(), { t } = useI18n()
const entries = ref<OrganizationDiscoveryDomain[]>([]), domain = ref(''), discovery = ref(true), from = ref(''), next = ref(''), attestation = ref<OrganizationDiscoveryDomain>()
const { loading, busy, error, reloadRequired, load, change } = usePanel(() => [props.tenant.host, props.organizationId], () => api.listOrganizationDomains(props.tenant, props.organizationId, from.value), r => { entries.value = r.domains; next.value = r.next ?? '' }, () => { entries.value = []; domain.value = ''; discovery.value = true; from.value = ''; next.value = ''; attestation.value = undefined })
const attestationOpen = computed({ get: () => !!attestation.value, set: (value: boolean) => { if (!value) attestation.value = undefined } })
const blocked = computed(() => loading.value || busy.value || !!error.value || reloadRequired.value)
function create() { if (blocked.value || !domain.value.trim()) return; const tn = props.tenant, id = props.organizationId, body = { domain: domain.value.trim(), status: 'pending' as const, use_for_organization_discovery: discovery.value }; void change(() => api.createOrganizationDomain(tn, id, body), async () => { domain.value = ''; from.value = ''; await load() }) }
function update(entry: OrganizationDiscoveryDomain, body: { status?: 'pending' | 'verified'; use_for_organization_discovery?: boolean }) { if (blocked.value) return; const tn = props.tenant, id = props.organizationId, did = entry.id; void change(() => api.updateOrganizationDomain(tn, id, did, body), async () => { attestation.value = undefined; await load() }) }
function remove(id: string) { const tn = props.tenant, org = props.organizationId; void change(() => api.deleteOrganizationDomain(tn, org, id)) }
function goto(cursor: string) { from.value = cursor; void load() }
</script>
<template>
 <div class="stack"><Banner v-if="error" kind="error">{{ error }} <Button :disabled="busy" @click="load">{{ t('retry') }}</Button></Banner><Banner v-if="reloadRequired" kind="error">{{ t('orgs.uncertain') }}</Banner><p>{{ t('orgs.domainHint') }}</p>
 <form class="card stack" @submit.prevent="create"><Field id="organization-domain" :label="t('orgs.domain')"><input id="organization-domain" v-model="domain" required /></Field><label><input v-model="discovery" type="checkbox" /> {{ t('orgs.useDiscovery') }}</label><Button type="submit" :disabled="blocked || !domain.trim()">{{ t('orgs.addDomain') }}</Button></form>
 <p v-if="loading" role="status">{{ t('loading') }}</p><section v-for="entry in entries" :key="entry.id" class="card stack"><h3>{{ entry.domain }}</h3><p>{{ t(entry.status === 'verified' ? 'orgs.verified' : 'orgs.pending') }}</p><dl><dt>{{ t('orgs.verificationHost') }}</dt><dd><code>{{ entry.verification_host }}</code></dd><dt>{{ t('orgs.verificationTXT') }}</dt><dd><code>{{ entry.verification_txt }}</code></dd></dl><label><input type="checkbox" :checked="entry.use_for_organization_discovery" :disabled="blocked" @change="update(entry, { use_for_organization_discovery: ($event.target as HTMLInputElement).checked })" /> {{ t('orgs.useDiscovery') }}</label><div class="row"><Button v-if="entry.status === 'pending'" :disabled="blocked" @click="attestation = entry">{{ t('orgs.attest') }}</Button><Button v-else :disabled="blocked" @click="update(entry, { status: 'pending' })">{{ t('orgs.markPending') }}</Button><Button variant="danger" :disabled="blocked" @click="remove(entry.id)">{{ t('orgs.removeDomain') }}</Button></div></section>
 <div class="row"><Button :disabled="blocked || !from" @click="goto('')">{{ t('orgs.firstPage') }}</Button><Button :disabled="blocked || !next" @click="goto(next)">{{ t('next') }}</Button></div>
 <Modal v-model:open="attestationOpen" :title="t('orgs.attestTitle')" :description="t('orgs.attestHint', { domain: attestation?.domain })"><template v-if="attestation"><Button data-attest :disabled="blocked" @click="update(attestation, { status: 'verified' })">{{ t('orgs.attestConfirm') }}</Button><Button :disabled="busy" @click="attestation = undefined">{{ t('cancel') }}</Button></template></Modal>
 </div>
</template>
