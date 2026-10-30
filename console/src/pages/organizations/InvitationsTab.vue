<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import type { OrganizationInvitation, OrganizationInvitationCreate, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import { usePanel } from './context'
const props = defineProps<{ tenant: SystemTenant; organizationId: string }>(), { api } = useServices(), { t } = useI18n()
const entries = ref<OrganizationInvitation[]>([]), page = ref(0), total = ref(0), inviter = ref(''), email = ref(''), client = ref(''), connection = ref(''), roles = ref(''), ttl = ref(604800), delivery = ref(true), url = ref(''), expires = ref(''), appMetadata = ref('{}'), userMetadata = ref('{}')
const { loading, busy, error, status, reloadRequired, load, change, capture, current } = usePanel(() => [props.tenant.host, props.organizationId], () => api.listOrganizationInvitations(props.tenant, props.organizationId, page.value), r => { entries.value = r.invitations ?? []; total.value = (r.invitations ?? []).length }, () => { entries.value = []; page.value = 0; total.value = 0; inviter.value = ''; email.value = ''; client.value = ''; connection.value = ''; roles.value = ''; ttl.value = 604800; delivery.value = true; url.value = ''; expires.value = ''; appMetadata.value = '{}'; userMetadata.value = '{}' })
const blocked = computed(() => loading.value || busy.value || !!error.value || reloadRequired.value)
async function create() {
 if (blocked.value) return
 let app: Record<string, unknown>, user: Record<string, unknown>
 try { app = JSON.parse(appMetadata.value); user = JSON.parse(userMetadata.value); if (!app || !user || typeof app !== 'object' || typeof user !== 'object' || Array.isArray(app) || Array.isArray(user)) throw new Error() } catch { status.value = t('orgs.jsonObject'); return }
 if (!inviter.value.trim() || !email.value.includes('@') || !client.value.trim() || !Number.isInteger(ttl.value) || ttl.value < 0 || ttl.value > 2592000) { status.value = t('orgs.invitationInvalid'); return }
 const tn = props.tenant, id = props.organizationId, mine = capture(), roleIds = roles.value.trim().split(/\s+/).filter(Boolean)
 const body: OrganizationInvitationCreate = { inviter: { name: inviter.value }, invitee: { email: email.value }, client_id: client.value, ttl_sec: ttl.value, send_invitation_email: delivery.value, app_metadata: app, user_metadata: user, ...(connection.value ? { connection_id: connection.value } : {}), ...(roleIds.length ? { roles: roleIds } : {}) }
 await change(async () => { const result = await api.createOrganizationInvitation(tn, id, body); if (current(mine)) { url.value = result.invitation_url ?? ''; expires.value = result.expires_at ?? ''; status.value = t('saved') } })
}
async function copy() { const mine = capture(), value = url.value; if (!value) return; try { await navigator.clipboard.writeText(value); if (current(mine)) status.value = t('orgs.copied') } catch (e) { if (current(mine)) status.value = errorMessage(e) } }
function remove(id?: string) { if (!id || blocked.value) return; const tn = props.tenant, org = props.organizationId; void change(() => api.deleteOrganizationInvitation(tn, org, id), async () => { url.value = ''; expires.value = ''; await load() }) }
function goto(next: number) { page.value = next; void load() }
</script>
<template>
 <div class="stack"><Banner v-if="error" kind="error">{{ error }} <Button :disabled="busy" @click="load">{{ t('retry') }}</Button></Banner><Banner v-if="reloadRequired" kind="error">{{ t('orgs.uncertain') }}</Banner>
 <p>{{ t('orgs.invitationHint') }}</p><form class="card stack" @submit.prevent="create">
 <Field id="inviter-name" :label="t('orgs.inviter')"><input id="inviter-name" v-model="inviter" required maxlength="300" /></Field>
 <Field id="invitee-email" :label="t('orgs.invitee')"><input id="invitee-email" v-model="email" type="email" required /></Field>
 <Field id="invitation-client" :label="t('orgs.clientID')"><input id="invitation-client" v-model="client" required /></Field>
 <Field id="invitation-connection" :label="t('orgs.optionalConnection')"><input id="invitation-connection" v-model="connection" /></Field>
 <Field id="invitation-roles" :label="t('orgs.invitationRoles')" :hint="t('orgs.roleScope')"><input id="invitation-roles" v-model="roles" /></Field>
 <Field id="invitation-ttl" :label="t('orgs.expiry')"><input id="invitation-ttl" v-model.number="ttl" type="number" min="0" max="2592000" required /></Field>
 <label><input id="invitation-delivery" v-model="delivery" type="checkbox" /> {{ t('orgs.delivery') }}</label>
 <Field id="invitation-app-metadata" :label="t('orgs.appMetadata')"><textarea id="invitation-app-metadata" v-model="appMetadata" /></Field><Field id="invitation-user-metadata" :label="t('orgs.userMetadata')"><textarea id="invitation-user-metadata" v-model="userMetadata" /></Field>
 <Button type="submit" :disabled="blocked">{{ t('orgs.createInvitation') }}</Button><span role="status">{{ status }}</span></form>
 <section v-if="url" class="card stack"><p>{{ t('orgs.expiresAt') }} {{ expires }}</p><Field id="invitation-url" :label="t('orgs.invitationURL')"><input id="invitation-url" :value="url" readonly /></Field><Button @click="copy">{{ t('orgs.copyInvitation') }}</Button></section>
 <p v-if="loading" role="status">{{ t('loading') }}</p><section v-for="entry in entries" :key="entry.id" class="card row"><span>{{ entry.invitee?.email }} — {{ entry.expires_at }}</span><code>{{ entry.roles?.join(', ') }}</code><Button variant="danger" :disabled="blocked" @click="remove(entry.id)">{{ t('orgs.revokeInvitation') }}</Button></section><div class="row"><Button :disabled="blocked || page === 0" @click="goto(page - 1)">{{ t('previous') }}</Button><Button :disabled="blocked || total < 20" @click="goto(page + 1)">{{ t('next') }}</Button></div>
 </div>
</template>
