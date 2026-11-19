<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import type { Connection, ConnectionKey, SystemTenant } from '../../../api/client'
import { errorMessage, useServices } from '../../../context'
import Banner from '../../../ui/Banner.vue'
import Button from '../../../ui/Button.vue'
import Field from '../../../ui/Field.vue'
import ConfirmDialog from '../../../ui/ConfirmDialog.vue'
const props = defineProps<{ tenant: SystemTenant; connection: Connection }>()
const { api } = useServices()
const keys = ref<ConnectionKey[]>([]), error = ref(''), loading = ref(false), busy = ref(false), confirm = ref(false)
const use = ref('signing'), signingAlg = ref('RS256'), encryptionAlg = ref('RSA-OAEP-256')
const algorithms = computed(() => use.value === 'signing' ? ['RS256','RS384','RS512','PS256','PS384','ES256','ES384'] : ['RSA-OAEP-256','RSA-OAEP-384','RSA-OAEP-512','ECDH-ES','ECDH-ES+A128KW','ECDH-ES+A192KW','ECDH-ES+A256KW'])
const algorithm = computed({ get: () => use.value === 'signing' ? signingAlg.value : encryptionAlg.value, set: value => { if (use.value === 'signing') signingAlg.value = value; else encryptionAlg.value = value } })
let generation = 0
watch(() => [props.tenant.name, props.connection.id], async () => { const mine = ++generation, tn = props.tenant, id = props.connection.id!; keys.value = []; error.value = ''; confirm.value = false; busy.value = false; loading.value = true; try { const result = await api.getConnectionKeys(tn,id); if (mine === generation) keys.value = result } catch (e) { if (mine === generation) error.value = errorMessage(e) } finally { if (mine === generation) loading.value = false } }, { immediate: true })
onBeforeUnmount(() => { generation++ })
async function write(rotate: boolean) {
 if (busy.value || props.tenant.seeded) return
 const mine = generation, tn = props.tenant, id = props.connection.id!
 const body = { key_use: use.value, [use.value === 'signing' ? 'signing_alg' : 'encryption_alg']: algorithm.value }
 error.value = ''; busy.value = true
 try {
  if (rotate) { await api.rotateConnectionKeys(tn,id,body); if (mine !== generation) return; const result = await api.getConnectionKeys(tn,id); if (mine !== generation) return; keys.value = result } else { const result = await api.createConnectionKeys(tn,id,body); if (mine !== generation) return; keys.value = result }
  confirm.value = false
 } catch (e) { if (mine === generation) error.value = errorMessage(e) } finally { if (mine === generation) busy.value = false }
}
async function copy(cert: string) { try { await navigator.clipboard.writeText(cert) } catch { error.value = 'Could not copy the certificate. Select and copy the public certificate below.' } }
</script>
<template>
 <section class="stack" aria-label="Connection keys"><Banner v-if="error" kind="error">{{ error }}</Banner><p v-if="loading" role="status">Loading public certificates…</p><p>Register a public certificate with your identity provider before switching authentication or encryption settings. Private keys stay on the server.</p>
 <Field id="enterprise-key-use" label="Key use"><select id="enterprise-key-use" v-model="use"><option value="signing">Signing</option><option value="encryption">Encryption</option></select></Field><Field id="enterprise-key-algorithm" label="Algorithm"><select id="enterprise-key-algorithm" v-model="algorithm"><option v-for="alg in algorithms" :key="alg">{{ alg }}</option></select></Field>
 <div class="row"><Button data-testid="create-keys" :disabled="loading || busy || tenant.seeded" @click="write(false)">Create keys</Button><Button data-testid="rotate-keys" :disabled="loading || busy || tenant.seeded" @click="confirm = true">Rotate keys</Button></div>
 <p v-if="!loading && !keys.length">No connection keys have been created.</p>
 <article v-for="key in keys" :key="key.kid" class="stack"><h3>{{ key.key_use }} · {{ key.current ? 'Current' : key.next ? 'Next' : 'Previous' }}</h3><code>{{ key.kid }}</code><p>{{ key.algorithm }} · {{ key.fingerprint }}</p><p v-if="key.current_since">Current since {{ key.current_since }}</p><textarea :aria-label="`Public certificate ${key.kid}`" :value="key.cert" readonly rows="6" spellcheck="false" /><Button @click="copy(key.cert)">Copy public certificate</Button></article>
 <ConfirmDialog v-model:open="confirm" title="Rotate connection keys?" description="The next key becomes current. Register its certificate with your provider before completing a rotation." confirm-label="Rotate keys" :busy="busy" :error="error" :danger="false" @confirm="write(true)" />
 </section>
</template>
