<script setup lang="ts">
import { ref, watch } from 'vue'
import type { Connection, SystemTenant } from '../../../api/client'
import { errorMessage, useServices } from '../../../context'
import Banner from '../../../ui/Banner.vue'
import Button from '../../../ui/Button.vue'
import Field from '../../../ui/Field.vue'
import { optionsOf, type Options } from '../social/social'
const props = defineProps<{ tenant: SystemTenant; connection: Connection }>()
const emit = defineEmits<{ saved: [Connection] }>()
const { api } = useServices()
const mode = ref('use_map'), attributes = ref('{}'), scope = ref(''), error = ref(''), status = ref(''), busy = ref(false)
const restricted = new Set(['user_id','identities','app_metadata','user_metadata','blocked','logins_count','last_login','last_ip','created_at','updated_at','password','password_hash','roles','permissions','sub','iss','aud','exp','iat','nonce','access_token','refresh_token','id_token','constructor','prototype'])
watch(() => [props.tenant.name, props.connection.id], () => { const map = optionsOf(props.connection).attribute_map as Options | undefined; mode.value = String(map?.mapping_mode ?? (props.connection.strategy === 'okta' ? 'basic_profile' : 'bind_all')); attributes.value = JSON.stringify(map?.attributes ?? {}, null, 2); scope.value = String(map?.userinfo_scope ?? ''); error.value = ''; status.value = ''; busy.value = false }, { immediate: true })
async function save() {
 if (busy.value || props.tenant.seeded) return
 error.value = ''; status.value = ''
 let values: Record<string,string>
 try { const value: unknown = JSON.parse(attributes.value); if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('Attributes must be a JSON object.'); values = value as Record<string,string>; if (Object.keys(values).length > 100) throw Error('Use at most 100 attributes.'); for (const [k,v] of Object.entries(values)) { if (restricted.has(k) || k.startsWith('_')) throw Error('This attribute is reserved.'); if (typeof v !== 'string' || new TextEncoder().encode(v).length > 1024) throw Error('Each template must be a string of at most 1024 bytes.') } } catch (e) { error.value = errorMessage(e); return }
 const options = { ...optionsOf(props.connection), attribute_map: { mapping_mode: mode.value, attributes: values, ...(scope.value ? { userinfo_scope: scope.value } : {}) } }
 delete (options as Options).client_secret
 const tn = props.tenant, id = props.connection.id!; busy.value = true
 try { const saved = await api.updateConnection(tn,id,{options}); if (props.tenant.name !== tn.name || props.connection.id !== id) return; status.value = 'Saved.'; emit('saved',saved) } catch (e) { if (props.tenant.name === tn.name && props.connection.id === id) error.value = errorMessage(e) } finally { if (props.tenant.name === tn.name && props.connection.id === id) busy.value = false }
}
</script>
<template>
 <form class="stack" @submit.prevent="save"><Banner v-if="error" kind="error">{{ error }}</Banner><p v-if="status" role="status">{{ status }}</p>
  <Field id="enterprise-mapping-mode" label="Mapping mode"><select id="enterprise-mapping-mode" v-model="mode"><option v-if="connection.strategy === 'oidc'" value="bind_all">Copy permitted claims</option><option v-else value="basic_profile">Basic profile</option><option value="use_map">Use attribute templates</option></select></Field>
  <Field id="enterprise-mapping" label="Attribute templates (JSON)" hint="For example: name maps to ${context.tokenset.name}. Userinfo references require a back-channel connection."><textarea id="enterprise-mapping" v-model="attributes" rows="10" spellcheck="false" /></Field>
  <Field id="enterprise-userinfo-scope" label="Userinfo scopes"><input id="enterprise-userinfo-scope" v-model="scope" /></Field>
  <p class="muted">The server validates the complete mapping and reports any unsupported target or template. Custom attributes appear in the identity profile.</p>
  <Button type="submit" variant="primary" :disabled="busy || tenant.seeded">Save mapping</Button>
 </form>
</template>
