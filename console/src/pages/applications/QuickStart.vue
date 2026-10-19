<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import type { Client, ClientGrant, SystemTenant } from '../../api/client'
import { errorMessage, useServices } from '../../context'
import { useI18n } from 'vue-i18n'
import Banner from '../../ui/Banner.vue'
import Button from '../../ui/Button.vue'
import CodeBlock from '../../ui/CodeBlock.vue'
import {
  authorizeURL,
  callCurl,
  expressConfig,
  nextjsEnv,
  spaJS,
  spaReact,
  tokenCurl,
  type AppFacts,
} from './snippets'

const { t } = useI18n()

// Ready-to-copy snippets for the application's type, with the tenant's
// host and the client ID filled in. The secret reaches a snippet only
// after "reveal".
const props = defineProps<{ tenant: SystemTenant; client: Client }>()
const { api } = useServices()

const revealed = ref(false)
const grants = ref<ClientGrant[]>([])
const loading = ref(false)
const error = ref('')

const facts = computed<AppFacts>(() => ({
  host: props.tenant.host,
  clientID: props.client.client_id,
  authMethod: props.client.token_endpoint_auth_method ?? 'client_secret_post',
  callbacks: props.client.callbacks ?? [],
}))
const secret = computed(() => (revealed.value && props.client.client_secret ? props.client.client_secret : null))
const hasSecret = computed(() => facts.value.authMethod !== 'none')
const type = computed(() => props.client.app_type)
const isBrowserOrNative = computed(() => type.value === 'spa' || type.value === 'native')
const wantsConnections = computed(() => type.value !== 'non_interactive')

async function load() {
  if (type.value !== 'non_interactive') return
  loading.value = true
  error.value = ''
  try {
    const all = await api.allClientGrants(props.tenant, { client_id: props.client.client_id })
    grants.value = all.filter((g) => g.subject_type === 'client')
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    loading.value = false
  }
}
onMounted(load)
</script>

<template>
  <div class="stack">
    <p class="muted">{{ t('quick.intro') }}</p>

    <div v-if="hasSecret && type !== 'spa' && type !== 'native'" class="card stack">
      <p v-if="!client.client_secret" class="muted" data-testid="no-secret">{{ t('quick.noSecretToReveal') }}</p>
      <template v-else>
        <p v-if="!revealed" class="muted" data-testid="secret-hidden">{{ t('quick.secretHidden') }}</p>
        <div class="row">
          <Button variant="ghost" :aria-pressed="revealed" data-testid="reveal" @click="revealed = !revealed">
            {{ revealed ? t('quick.hideSecret') : t('quick.revealSecret') }}
          </Button>
        </div>
      </template>
    </div>

    <template v-if="type === 'non_interactive'">
      <Banner v-if="error" kind="error">
        {{ error }}
        <Button variant="ghost" @click="load">{{ t('retry') }}</Button>
      </Banner>
      <p v-else-if="loading" class="muted" role="status">{{ t('loading') }}</p>
      <div v-else-if="grants.length === 0" class="card" data-testid="m2m-empty">
        <p>{{ t('quick.m2mNoGrants') }}</p>
      </div>
      <template v-else>
        <p v-if="!hasSecret" class="muted">{{ t('quick.m2mPublic') }}</p>
        <section v-for="g in grants" :key="g.id" class="card stack" :data-testid="'m2m-' + g.audience">
          <CodeBlock :title="t('quick.m2mStep1', { audience: g.audience })" :code="tokenCurl(facts, g.audience, secret)" />
          <CodeBlock :title="t('quick.m2mStep2')" :code="callCurl(g.audience)" />
        </section>
      </template>
    </template>

    <template v-else-if="isBrowserOrNative">
      <section class="card stack">
        <p class="muted">{{ t('quick.authorizeHint') }}</p>
        <CodeBlock :title="t('quick.authorizeTitle')" :code="authorizeURL(facts)" />
      </section>
      <section class="card stack">
        <CodeBlock :title="t('quick.spaTitle')" :code="spaJS(facts)" />
        <CodeBlock :title="t('quick.reactTitle')" :code="spaReact(facts)" />
      </section>
    </template>

    <template v-else>
      <section class="card stack">
        <CodeBlock :title="t('quick.nextTitle')" :code="nextjsEnv(facts, secret)" />
        <CodeBlock :title="t('quick.expressTitle')" :code="expressConfig(facts, secret)" />
      </section>
    </template>

    <section v-if="wantsConnections" class="card" data-testid="connections-note">
      <h2>{{ t('quick.connectionTitle') }}</h2>
      <p class="muted">{{ t('quick.connectionNone') }}</p>
    </section>
  </div>
</template>

<style scoped>
h2 {
  margin: 0 0 0.35rem;
  font-size: 1.05rem;
}
p {
  margin: 0;
}
</style>
