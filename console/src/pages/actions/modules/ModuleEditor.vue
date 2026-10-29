<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import type { ActionModule } from '../../../api/client'
import Banner from '../../../ui/Banner.vue'
import Button from '../../../ui/Button.vue'
import Field from '../../../ui/Field.vue'
import CodeEditor from '../../connections/CodeEditor.vue'
import DraftConfiguration from '../DraftConfiguration.vue'
import { useDraftEditor } from '../useDraftEditor'
import ActionNav from '../ActionNav.vue'
import { buildStatusKey, useActionContext } from '../context'
const { t } = useI18n(), ctx = useActionContext(), { api, tenant, id } = ctx
const { resource: action, name, code, dependencies, secrets, loading, busy, error, notice, reloadRequired, dirty, read, save, reload, publish: deploy } = useDraftEditor<ActionModule>({
 context: ctx,
 limits: { name: 255, code: 65536, codeUnit: 'characters', invalid: 'actions.invalidModuleDraft' },
 read: (tenant, id) => api.getActionModule(tenant, id),
 update: (tenant, id, { code, dependencies, secrets }) => api.updateActionModule(tenant, id, { code, dependencies, secrets }),
 publish: async (tenant, id, value) => {
  const version = await api.publishActionModule(tenant, id)
  return { ...value, latest_version: version, latest_version_number: version.version_number, all_changes_published: true }
 },
 published: 'actions.published',
})
</script>
<template>
  <div v-if="tenant" class="stack">
    <ActionNav /><RouterLink :to="{ name: 'action-module-versions', params: { tenant: tenant.name, id } }">{{ t('actions.versions') }}</RouterLink><h1>{{ t('actions.moduleEditor') }}</h1>
    <Banner v-if="error" kind="error">{{ error }}</Banner><Banner v-if="notice">{{ notice }}</Banner>
    <p v-if="loading" role="status">{{ t('loading') }}</p>
    <template v-if="action">
      <section class="card stack" :aria-label="t('actions.buildStatus')">
        <div class="row"><strong>{{ action.name }}</strong><span class="flex-1" /><span role="status">{{ t(buildStatusKey(action.status)) }}</span></div>
        <p class="muted"><span v-if="action.latest_version_number">{{ t('actions.versionNumber', { number: action.latest_version_number }) }}</span></p>
        <ul v-if="action.errors?.length" role="alert"><li v-for="(message, i) in action.errors" :key="i">{{ message }}</li></ul>
        <Button :disabled="busy || reloadRequired || dirty || action.status !== 'built'" @click="deploy">{{ t('actions.publish') }}</Button>
        <p class="muted">{{ t('actions.publishHint') }}</p>
      </section>
      <form class="stack" @submit.prevent="save">
        <fieldset :disabled="busy" class="stack border-0 p-0">
          <Field id="action-name" :label="t('actions.name')"><input id="action-name" v-model="name" readonly /></Field>
          <CodeEditor id="action-code" v-model="code" :label="t('actions.code')" :readonly="busy"  />
          <p class="muted">{{ t('actions.moduleCodeHint', { used: [...code].length }) }}</p>
          <DraftConfiguration v-model:dependencies="dependencies" v-model:secrets="secrets" />
        </fieldset>
        <div class="row"><Button type="submit" variant="primary" :disabled="busy || reloadRequired">{{ t('actions.save') }}</Button><Button v-if="reloadRequired" :disabled="busy" @click="reload">{{ t('actions.reload') }}</Button></div>
        <p v-if="reloadRequired" class="muted">{{ t('actions.reloadHint') }}</p>
      </form>
    </template>
    <Button v-else-if="error" @click="read()">{{ t('retry') }}</Button>
  </div>
  <Banner v-else kind="error">{{ t('unknownTenant') }}</Banner>
</template>
