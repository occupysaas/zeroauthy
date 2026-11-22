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
const domains = ref(''), display = ref(''), icon = ref(''), show = ref(true), error = ref(''), status = ref(''), busy = ref(false)
watch(() => [props.tenant.name, props.connection.id], () => { const o = optionsOf(props.connection); domains.value = ((o.domain_aliases as string[] | undefined) ?? []).join('\n'); icon.value = String(o.icon_url ?? ''); display.value = props.connection.display_name ?? ''; show.value = props.connection.show_as_button !== false; error.value = ''; status.value = ''; busy.value = false }, { immediate: true })
async function save() { if (busy.value || props.tenant.seeded) return; error.value = ''; status.value = ''; const options: Options = { ...optionsOf(props.connection), domain_aliases: [...new Set(domains.value.split(/\r?\n/).map(v => v.trim().toLowerCase()).filter(Boolean))], icon_url: icon.value }; delete options.client_secret; const tn = props.tenant, id = props.connection.id!; busy.value = true; try { const saved = await api.updateConnection(tn,id,{options,display_name:display.value,show_as_button:show.value}); if (props.tenant.name !== tn.name || props.connection.id !== id) return; status.value = 'Saved.'; emit('saved',saved) } catch (e) { if (props.tenant.name === tn.name && props.connection.id === id) error.value = errorMessage(e) } finally { if (props.tenant.name === tn.name && props.connection.id === id) busy.value = false } }
</script>
<template><form class="stack" @submit.prevent="save"><Banner v-if="error" kind="error">{{ error }}</Banner><p v-if="status" role="status">{{ status }}</p><Field id="enterprise-domains" label="Home realm domains" hint="One domain per line, up to 1000. Identifier-first login matches exact email domains without looking up accounts."><textarea id="enterprise-domains" v-model="domains" rows="5" /></Field><Field id="enterprise-display" label="Button label"><input id="enterprise-display" v-model="display" /></Field><Field id="enterprise-icon" label="Icon URL"><input id="enterprise-icon" v-model="icon" type="url" /></Field><label class="check"><input v-model="show" type="checkbox" /> Show this connection as a login button</label><Button type="submit" variant="primary" :disabled="busy || tenant.seeded">Save login experience</Button></form></template>
