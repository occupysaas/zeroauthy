<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { LogEvent } from '../../api/client'
import { errorMessage } from '../../context'
import { executionIDs, unavailable, useMonitoringContext } from './shared'
import Banner from '../../ui/Banner.vue'
import RouteModal from '../../ui/RouteModal.vue'
const { t } = useI18n(), { api, tenant, key, capture, current } = useMonitoringContext()
const log = ref<LogEvent>(), error = ref(''), missing = ref(false), busy = ref(false)
async function load() {
 const c = capture(); log.value = undefined; error.value = ''; missing.value = false; busy.value = false
 if (!c) return
 busy.value = true
 try { const r = await api.getLog(c.tenant, c.id); if (current(c)) log.value = r }
 catch(e) { if(current(c)) { missing.value = unavailable(e); error.value = missing.value ? '' : errorMessage(e) } }
 finally { if(current(c)) busy.value = false }
}
watch(key, load, { immediate: true })
</script>
<template>
 <RouteModal :title="t('monitor.logDetail')" back="logs" wide><div v-if="tenant" class="stack">
 <Banner v-if="missing" kind="warn">{{ t('monitor.unavailable') }}</Banner><Banner v-else-if="error" kind="error">{{ error }}</Banner><p v-if="busy" role="status">{{ t('loading') }}</p>
 <template v-if="log"><dl class="card grid gap-2"><dt>{{ t('monitor.time') }}</dt><dd>{{ log.date }}</dd><dt>{{ t('monitor.type') }}</dt><dd>{{ log.type }}</dd><dt>{{ t('monitor.description') }}</dt><dd>{{ log.description }}</dd></dl>
 <nav class="row flex-wrap" :aria-label="t('monitor.related')"><RouterLink v-if="log.user_id" :to="{ name: 'user', params: { tenant: tenant.name, id: log.user_id } }">{{ t('monitor.user') }} {{ log.user_id }}</RouterLink><RouterLink v-if="log.client_id" :to="{ name: 'application', params: { tenant: tenant.name, id: log.client_id } }">{{ t('monitor.application') }} {{ log.client_id }}</RouterLink><RouterLink v-for="id in executionIDs(log.details)" :key="id" :to="{ name: 'execution-view', params: { tenant: tenant.name, id } }">{{ t('monitor.execution') }} {{ id }}</RouterLink></nav>
 <h2>{{ t('monitor.json') }}</h2><p class="muted">{{ t('monitor.redaction') }}</p><pre class="card max-w-full overflow-auto whitespace-pre-wrap break-all">{{ JSON.stringify(log, null, 2) }}</pre></template></div><Banner v-else kind="error">{{ t('unknownTenant') }}</Banner></RouteModal>
</template>
