<script setup lang="ts">
import { ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ApiError, type ActionModule, type ActionModuleActionsPage } from '../../../api/client'
import { errorMessage } from '../../../context'
import Banner from '../../../ui/Banner.vue'
import Button from '../../../ui/Button.vue'
import Field from '../../../ui/Field.vue'
import Modal from '../../../ui/Modal.vue'
import Pager from '../../roles/Pager.vue'
import ActionNav from '../ActionNav.vue'
import { buildStatusKey, useActionContext } from '../context'
const { t } = useI18n(), router = useRouter(), { api, tenant, key, capture, current } = useActionContext()
const items = ref<ActionModule[]>([]), page = ref(0), total = ref(0), loading = ref(false), busy = ref(false), error = ref(''), name = ref(''), creating = ref(false), deleting = ref(false), selected = ref<ActionModule>(), users = ref<ActionModuleActionsPage>(), userPage = ref(0)
let reads = 0, userReads = 0, modalGeneration = 0
let deletion: ReturnType<typeof capture>
async function load() {
 const c = capture(), seq = ++reads
 if (!c) return
 loading.value = true; error.value = ''
 try { const r = await api.listActionModules(c.tenant, { page: page.value, per_page: 20 }); if (current(c) && seq === reads) { items.value = r.modules; total.value = r.total } }
 catch(e) { if(current(c) && seq === reads) error.value = errorMessage(e) }
 finally { if(current(c) && seq === reads) loading.value = false }
}
watch(key, () => { ++userReads; page.value = 0; items.value = []; total.value = 0; selected.value = undefined; users.value = undefined; deleting.value = false; creating.value = false; busy.value = false; void load() }, { immediate: true })
async function create() {
 const c = capture(); if (!c || busy.value || !name.value.trim()) return
 busy.value = true; error.value = ''
 try { const m = await api.createActionModule(c.tenant, { name: name.value, code: '' }); if(current(c)) await router.push({ name: 'action-module-editor', params: { tenant: c.tenant.name, id: m.id } }) }
 catch(e) { if(current(c)) error.value = errorMessage(e) }
 finally { if(current(c)) busy.value = false }
}
watch(deleting, () => { ++modalGeneration; ++userReads; busy.value = false }, { flush: 'sync' })
function ask(m: ActionModule) { ++modalGeneration; ++userReads; busy.value = false; deletion = capture(); selected.value = m; users.value = undefined; userPage.value = 0; error.value = ''; deleting.value = true }
async function loadUsers(n = 0) {
 const c = deletion, id = selected.value?.id, seq = ++userReads; if(!c || !current(c) || !id) return
 userPage.value = n
 try { const r = await api.listActionModuleActions(c.tenant, id, { page: n, per_page: 20 }); if(current(c) && deleting.value && seq === userReads && selected.value?.id === id) users.value = r }
 catch(e) { if(current(c) && seq === userReads) error.value = errorMessage(e) }
}
async function remove() {
 const c = deletion, m = selected.value, generation = modalGeneration; if(!c || !current(c) || !m || busy.value || users.value) return
 const active = () => current(c) && deleting.value && modalGeneration === generation && selected.value?.id === m.id
 busy.value = true; error.value = ''
 try { await api.deleteActionModule(c.tenant, m.id); if(active()) { deleting.value = false; await load() } }
 catch(e) { if(active()) { error.value = errorMessage(e); if(e instanceof ApiError && e.status === 412) await loadUsers() } }
 finally { if(active()) busy.value = false }
}
function goto(n: number) { page.value = n; void load() }
</script>
<template>
 <div v-if="tenant" class="stack">
 <ActionNav /><div class="row"><h1>{{ t('actions.modules') }}</h1><Button @click="creating = true">{{ t('actions.createModule') }}</Button></div>
 <p>{{ t('actions.modulesHint') }}</p><Banner v-if="error && !deleting" kind="error">{{ error }} <Button @click="load">{{ t('retry') }}</Button></Banner>
 <p v-if="loading" role="status">{{ t('loading') }}</p>
 <table v-else-if="items.length" class="data"><thead><tr><th scope="col">{{ t('actions.name') }}</th><th scope="col">{{ t('actions.status') }}</th><th scope="col">{{ t('actions.manage') }}</th></tr></thead><tbody><tr v-for="m in items" :key="m.id"><td><RouterLink :to="{ name: 'action-module-editor', params: { tenant: tenant.name, id: m.id } }">{{ m.name }}</RouterLink></td><td>{{ t(buildStatusKey(m.status)) }}</td><td><Button @click="ask(m)">{{ t('actions.delete') }}</Button></td></tr></tbody></table><p v-else>{{ t('actions.noModules') }}</p>
 <Pager :page="page" :total="total" :busy="loading" @change="goto" />
 <Modal v-model:open="creating" :title="t('actions.createModule')" :description="t('actions.modulesHint')"><form class="stack" @submit.prevent="create"><Field id="module-name" :label="t('actions.name')"><input id="module-name" v-model="name" required maxlength="255" :disabled="busy" /></Field><div class="row"><Button type="submit" variant="primary" :disabled="busy">{{ t('actions.createModule') }}</Button><Button @click="creating = false">{{ t('cancel') }}</Button></div><Banner v-if="error" kind="error">{{ error }}</Banner></form></Modal>
 <Modal v-model:open="deleting" :title="t('actions.deleteNamed', { name: selected?.name })" :description="t('actions.moduleDeleteHint')">
 <Banner v-if="error" kind="error">{{ error }}</Banner><template v-if="users"><p>{{ t('actions.moduleUsers', { count: users.total }) }}</p><ul><li v-for="a in users.actions" :key="a.action_id"><RouterLink :to="{ name: 'action-editor', params: { tenant: tenant.name, id: a.action_id } }">{{ a.action_name }}</RouterLink> · {{ t('actions.versionNumber', { number: a.module_version_number }) }}</li></ul><Pager :page="userPage" :total="users.total" :busy="busy" @change="loadUsers" /></template>
 <div class="row"><Button data-testid="confirm-delete" variant="danger" :disabled="busy || !!users" @click="remove">{{ t('actions.confirmDelete') }}</Button><Button @click="deleting = false">{{ t('cancel') }}</Button></div>
 </Modal></div><Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
