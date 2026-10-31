<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { SystemExecution } from '../../api/client'
import { errorMessage } from '../../context'
import { unavailable, useMonitoringContext } from '../logs/shared'
import Banner from '../../ui/Banner.vue'
import ActionNav from './ActionNav.vue'
import ExecutionResults from './ExecutionResults.vue'
const { t } = useI18n(), { api, tenant, key, capture, current } = useMonitoringContext()
const execution = ref<SystemExecution>(), error = ref(''), missing = ref(false), busy = ref(false)
async function load() {
 const c = capture(); execution.value = undefined; error.value = ''; missing.value = false; busy.value = false
 if (!c) return
 busy.value = true
 try { const r = await api.getExecution(c.tenant, c.id); if (current(c)) execution.value = r }
 catch(e) { if(current(c)) { missing.value = unavailable(e); error.value = missing.value ? '' : errorMessage(e) } }
 finally { if(current(c)) busy.value = false }
}
watch(key, load, { immediate: true })
</script>
<template><div v-if="tenant" class="stack"><ActionNav /><h1>{{ t('monitor.execution') }}</h1><Banner v-if="missing" kind="warn">{{ t('monitor.unavailable') }}</Banner><Banner v-else-if="error" kind="error">{{ error }}</Banner><p v-if="busy" role="status">{{ t('loading') }}</p><template v-if="execution"><code>{{ execution.id }}</code><ExecutionResults :execution="execution" :tenant-name="tenant.name" /></template></div><Banner v-else kind="error">{{ t('unknownTenant') }}</Banner></template>
