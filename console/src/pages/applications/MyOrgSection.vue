<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import type { Client, ClientGrant, ResourceServer, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
import GrantForm from '../apis/GrantForm.vue'

// The application's access to the My Organization API (Plan 42b): the
// user grant and its my_organization_configuration.
const props = defineProps<{ tenant: SystemTenant; client: Client; api: ResourceServer; grant: ClientGrant | null }>()
const emit = defineEmits<{ grant: [ClientGrant | null] }>()
const { t } = useI18n()
const { api: services } = useServices()
const strategies = ['adfs', 'google-apps', 'oidc', 'okta', 'pingfederate', 'samlp', 'waad'] as const
const busy = ref(false)
const error = ref('')
const status = ref('')
const clients = ref<Client[]>([])
const current = props.client.my_organization_configuration
const form = reactive({
  landing: current?.invitation_landing_client_id ?? '',
  deletion: current?.connection_deletion_behavior ?? 'allow',
  ceiling: current?.enforce_permission_ceiling ?? false,
  selfAssign: current?.enforce_self_assignment_restriction ?? false,
  strategies: [...(current?.allowed_strategies ?? [])] as string[],
})
const configured = ref(!!current)

onMounted(async () => {
  try {
    clients.value = await services.allClients(props.tenant)
  } catch (e) {
    error.value = errorMessage(e)
  }
})

async function allow() {
  busy.value = true
  error.value = ''
  try {
    emit('grant', await services.createClientGrant(props.tenant, { client_id: props.client.client_id, audience: props.api.identifier, subject_type: 'user', scope: (props.api.scopes ?? []).map((s) => s.value) }))
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}

async function remove() {
  if (!props.grant) return
  error.value = ''
  try {
    await services.deleteClientGrant(props.tenant, props.grant.id)
    emit('grant', null)
  } catch (e) {
    error.value = errorMessage(e)
  }
}

async function save(clear: boolean) {
  busy.value = true
  error.value = ''
  status.value = ''
  const cfg = clear
    ? null
    : {
        allowed_strategies: form.strategies as (typeof strategies)[number][],
        connection_deletion_behavior: form.deletion as 'allow' | 'allow_if_empty',
        ...(form.landing ? { invitation_landing_client_id: form.landing } : {}),
        enforce_permission_ceiling: form.ceiling,
        enforce_self_assignment_restriction: form.selfAssign,
      }
  try {
    await services.updateClient(props.tenant, props.client.client_id, { my_organization_configuration: cfg })
    configured.value = !clear
    status.value = t('saved')
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <section class="card stack" data-testid="my-org-access">
    <h2 class="m-0 text-[1.05rem]">{{ t('grants.myOrg.title') }}</h2>
    <p class="m-0 muted">{{ t('grants.myOrg.hint') }}</p>
    <Banner v-if="error" kind="error">{{ error }}</Banner>
    <template v-if="grant">
      <GrantForm :tenant="tenant" :api="api" :grant="grant" @saved="(g) => emit('grant', g)" />
      <div class="row"><Button variant="danger" @click="remove">{{ t('grants.myAccount.remove') }}</Button></div>
    </template>
    <div v-else class="row"><Button variant="primary" :disabled="busy" @click="allow">{{ t('grants.myAccount.allow') }}</Button></div>
    <form class="stack" data-testid="my-org-config" novalidate @submit.prevent="save(false)">
      <h3 class="m-0 text-[1rem]">{{ t('grants.myOrg.config') }}</h3>
      <Field id="my-org-landing" :label="t('grants.myOrg.landing')">
        <select id="my-org-landing" v-model="form.landing">
          <option value="">{{ t('grants.myOrg.landingNone') }}</option>
          <option v-for="c in clients" :key="c.client_id" :value="c.client_id">{{ c.name }} ({{ c.client_id }})</option>
        </select>
      </Field>
      <Field id="my-org-deletion" :label="t('grants.myOrg.deletion')">
        <select id="my-org-deletion" v-model="form.deletion">
          <option value="allow">allow</option>
          <option value="allow_if_empty">allow_if_empty</option>
        </select>
      </Field>
      <fieldset class="stack">
        <legend>{{ t('grants.myOrg.strategies') }}</legend>
        <label v-for="s in strategies" :key="s" class="row"><input v-model="form.strategies" type="checkbox" :value="s" /> {{ s }}</label>
      </fieldset>
      <label class="row"><input id="my-org-ceiling" v-model="form.ceiling" type="checkbox" /> {{ t('grants.myOrg.ceiling') }}</label>
      <label class="row"><input id="my-org-self" v-model="form.selfAssign" type="checkbox" /> {{ t('grants.myOrg.selfAssign') }}</label>
      <div class="row">
        <Button type="submit" variant="primary" :disabled="busy">{{ t('grants.myOrg.save') }}</Button>
        <Button v-if="configured" type="button" variant="danger" :disabled="busy" @click="save(true)">{{ t('grants.myOrg.remove') }}</Button>
        <span role="status">{{ status }}</span>
      </div>
    </form>
  </section>
</template>
