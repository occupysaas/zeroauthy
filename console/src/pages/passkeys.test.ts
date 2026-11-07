import { defineComponent, h, ref } from 'vue'
import { flushPromises } from '@vue/test-utils'
import { afterEach, expect, it } from 'vitest'
import { mountAt, confirmPrompt } from '../test/mount'
import { client, connection, tenant, type Call, type Reply } from '../test/services'
import PasswordTab from './connections/PasswordTab.vue'
import SettingsTab from './applications/SettingsTab.vue'
import UserMfa from './users/UserMfa.vue'
import Mfa from './security/Mfa.vue'
const factors = ['otp', 'webauthn-roaming', 'webauthn-platform']
function respond(c: Call): Reply {
 if(c.url.endsWith('passkey-prerequisites')) return {status:200,body:{effective:false,unmet:['identifier_first']}}
 if(c.url.endsWith('webauthn-roaming/settings')) return {status:200,body:c.method==='PUT'?c.body:{user_verification:'preferred'}}
 if(c.url.endsWith('/guardian/factors')) return {status:200,body:factors.map(name=>({name,enabled:name==='webauthn-platform',requires_other_factor:name==='webauthn-platform'}))}
 if(c.url.endsWith('/guardian/policies')) return {status:200,body:[]}
 if(c.url.includes('/authentication-methods')) return {status:200,body:[{id:'passkey|one',type:'passkey',name:'Laptop',relying_party_identifier:'login.example.test',credential_device_type:'multi_device',credential_backed_up:true,aaguid:'model-id',created_at:'2026-11-01T00:00:00Z'}, {id:'webauthn|one',type:'webauthn-roaming',name:'Security key',relying_party_identifier:'keys.example.test'}]}
 if(c.method==='PATCH' && c.url.includes('/clients/')) return {status:200,body:client('app', c.body as object)}
 if(c.method==='PATCH') return {status:200,body:connection('db',c.body as object)}
 return {status:200,body:{}}
}
afterEach(()=>{document.body.innerHTML=''})
it('blocks passkey enablement on server prerequisites and links each prerequisite',async()=>{
 const page=defineComponent({render:()=>h(PasswordTab,{tenant:tenant('acme'),connection:connection('db')})})
 const {wrapper,calls}=await mountAt(page,'/t/acme/connections/database/db',respond)
 expect(wrapper.find('#passkey-enabled').exists()).toBe(true)
 expect(wrapper.get('#passkey-enabled').attributes('disabled')).toBeDefined()
 expect(wrapper.findAll('[data-prerequisite]')).toHaveLength(5)
 expect(wrapper.findAll('[data-prerequisite] a')).toHaveLength(5)
 expect(wrapper.get('#passkey-ui').findAll('option').map(x=>x.attributes('value'))).toEqual(['both','autofill','button'])
 expect(wrapper.find('#passkey-progressive').exists()).toBe(true); expect(wrapper.find('#passkey-local').exists()).toBe(true)
 expect(calls.some(c=>c.url.endsWith('/connections/db/passkey-prerequisites'))).toBe(true);wrapper.unmount()
})
it('uses enforced WebAuthn labels, server platform warning and extension UV settings',async()=>{
 const {wrapper,calls}=await mountAt(Mfa,'/t/acme/mfa',respond)
 expect(wrapper.get('[data-factor="webauthn-roaming"]').text()).not.toContain('Plan 33b')
 expect(wrapper.text()).toContain('another enabled factor')
 expect((wrapper.get('#webauthn-uv').element as HTMLSelectElement).value).toBe('preferred')
 await wrapper.get('#webauthn-uv').setValue('required');await flushPromises()
 expect(calls.find(c=>c.method==='PUT' && c.url.endsWith('webauthn-roaming/settings'))?.body).toEqual({user_verification:'required'});wrapper.unmount()
})
it('requests only the safe system projection and separates passkey metadata from MFA',async()=>{
 const page=defineComponent({render:()=>h(UserMfa,{tenant:tenant('acme'),user:{user_id:'auth0|1'}})})
 const {wrapper,calls}=await mountAt(page,'/t/acme/users/auth0%7C1',respond)
 expect(calls[0]?.url).toContain('/api/system/tenants/acme/users/auth0%7C1/authentication-methods')
 expect(wrapper.get('[data-passkeys]').text()).toContain('Laptop');expect(wrapper.get('[data-passkeys]').text()).toContain('model-id')
 expect(wrapper.get('[data-mfa-methods]').text()).toContain('keys.example.test')
 expect(calls.some(c=>/public_key|user_handle/.test(c.url))).toBe(false)
 await wrapper.get('#delete-passkey-0').trigger('click');await confirmPrompt()
 expect(calls.some(c=>c.method==='DELETE'&&c.url.endsWith('/authentication-methods/passkey%7Cone'))).toBe(true);wrapper.unmount()
})
it('saves the passkey grant and native Device Settings while preserving other grants',async()=>{
 const page=defineComponent({render:()=>h(SettingsTab,{tenant:tenant('acme'),client:client('app')})})
 const {wrapper,calls}=await mountAt(page,'/t/acme/applications/app',respond)
 await wrapper.get('#app-passkey-grant').setValue(true)
 await wrapper.get('#app-ios-team').setValue('TEAM');await wrapper.get('#app-ios-bundle').setValue('com.example.app')
 await wrapper.get('#app-android-package').setValue('com.example.android');await wrapper.get('#app-android-fingerprints').setValue('fingerprint')
 await wrapper.get('form').trigger('submit');await flushPromises()
 const body=calls.find(c=>c.method==='PATCH')?.body as Record<string,unknown>
 expect(body.grant_types).toEqual(['authorization_code','refresh_token','client_credentials','urn:okta:params:oauth:grant-type:webauthn'])
 expect(body.mobile).toEqual({ios:{team_id:'TEAM',app_bundle_identifier:'com.example.app'},android:{app_package_name:'com.example.android',sha256_cert_fingerprints:['fingerprint']}});wrapper.unmount()
})
it('drops stale passkey prerequisites after tenant changes',async()=>{
 const selected=ref(tenant('acme'));let finish!:(r:Reply)=>void
 const page=defineComponent({render:()=>h(PasswordTab,{tenant:selected.value,connection:connection('db')})})
 const {wrapper}=await mountAt(page,'/t/acme/connections/database/db',c=>c.url.includes('/tenants/acme/')?new Promise(r=>{finish=r}):{status:200,body:{effective:false,unmet:[]}})
 selected.value=tenant('system');await flushPromises();finish({status:200,body:{effective:false,unmet:['identifier_first']}});await flushPromises()
 expect(wrapper.get('#passkey-enabled').attributes('disabled')).toBeUndefined();wrapper.unmount()
})
it('renames a passkey using the safe system route and ignores a stale mutation reply',async()=>{
 const selected=ref(tenant('acme'));let finish!:(r:Reply)=>void
 const page=defineComponent({render:()=>h(UserMfa,{tenant:selected.value,user:{user_id:'auth0|1'}})})
 const {wrapper,calls}=await mountAt(page,'/t/acme/users/auth0%7C1',c=>c.method==='PATCH'?new Promise(r=>{finish=r}):respond(c))
 await wrapper.get('#rename-passkey-0').trigger('click');await flushPromises(); const input = document.querySelector<HTMLInputElement>('#passkey-name')!; input.value = 'New laptop'; input.dispatchEvent(new Event('input', { bubbles: true })); document.querySelector<HTMLFormElement>('#rename-passkey-form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));await flushPromises()
 expect(calls.at(-1)?.url).toContain('/api/system/tenants/acme/users/auth0%7C1/authentication-methods/passkey%7Cone')
 expect(calls.at(-1)?.body).toEqual({name:'New laptop'})
 selected.value=tenant('system');await flushPromises();finish({status:200,body:{id:'passkey|one',type:'passkey',name:'Stale laptop'}});await flushPromises()
 expect(wrapper.text()).not.toContain('Stale laptop');wrapper.unmount()
})
it('preserves server RP invalidity, operator aliases and port origins',async()=>{
 const {default:RelyingPartyIds}=await import('./settings/RelyingPartyIds.vue')
 const {wrapper}=await mountAt(RelyingPartyIds,'/t/acme/settings/relying-party-ids',()=>({status:200,body:[
  {host:'acme.example.test',kind:'canonical',origin:'https://acme.example.test',relying_party_identifier:'acme.example.test',valid:true},
  {host:'alias.example.test:9543',kind:'operator',origin:'https://alias.example.test:9543',relying_party_identifier:'example.test',valid:false},
  {host:'login.customer.test',kind:'custom',origin:'https://login.customer.test',relying_party_identifier:'customer.test',valid:true,custom_domain_id:'domain1'},
 ]}))
 expect(wrapper.findAll('tbody tr')).toHaveLength(3)
 expect(wrapper.get('[data-host="alias.example.test:9543"]').text()).toContain('Invalid')
 expect(wrapper.get('[data-host="login.customer.test"] a').attributes('href')).toContain('domain1')
 expect(wrapper.text()).toContain('stop working');wrapper.unmount()
})
it('saves passkey choices without removing unrelated connection options and ignores a stale save',async()=>{
 const selected=ref(tenant('acme'));let finish!:(r:Reply)=>void
 const saved=connection('db',{options:{authentication_methods:{password:{enabled:true},passkey:{enabled:false}},passkey_options:{challenge_ui:'both',unknown_option:'retain'},custom_option:{keep:true}}})
 const page=defineComponent({render:()=>h(PasswordTab,{tenant:selected.value,connection:saved})})
 const {wrapper,calls}=await mountAt(page,'/t/acme/connections/database/db',c=>c.method==='PATCH'?new Promise(r=>{finish=r}):{status:200,body:{effective:false,unmet:[]}})
 await wrapper.get('#passkey-enabled').setValue(true);await wrapper.get('#passkey-ui').setValue('autofill');await wrapper.get('#passkey-progressive').setValue(false)
 await wrapper.get('#passkey-settings').trigger('submit');await flushPromises()
 expect(calls.at(-1)?.body).toEqual({options:{authentication_methods:{password:{enabled:true},passkey:{enabled:true}},passkey_options:{challenge_ui:'autofill',progressive_enrollment_enabled:false,local_enrollment_enabled:true,unknown_option:'retain'},custom_option:{keep:true}}})
 selected.value=tenant('system');await flushPromises();finish({status:200,body:connection('db',{name:'Old saved connection'})});await flushPromises()
 expect(wrapper.text()).not.toContain('Saved');wrapper.unmount()
})
it('drops a stale UV setting error after tenant navigation',async()=>{
 let finish!:(r:Reply)=>void
 const {wrapper,router}=await mountAt(Mfa,'/t/acme/mfa',c=>c.method==='PUT'&&c.url.endsWith('webauthn-roaming/settings')?new Promise(r=>{finish=r}):respond(c))
 await wrapper.get('#webauthn-uv').setValue('required');await router.push('/t/system/mfa');await flushPromises()
 finish({status:400,body:{message:'Old tenant UV error'}});await flushPromises()
 expect(wrapper.text()).not.toContain('Old tenant UV error');expect((wrapper.get('#webauthn-uv').element as HTMLSelectElement).value).toBe('preferred');wrapper.unmount()
})
it('drops stale RP host status after A to B to A navigation',async()=>{
 const {default:RelyingPartyIds}=await import('./settings/RelyingPartyIds.vue');let finish!:(r:Reply)=>void;let first=true
 const {wrapper,router}=await mountAt(RelyingPartyIds,'/t/acme/settings/relying-party-ids',()=>{
  if(first){first=false;return new Promise(r=>{finish=r})}
  return {status:200,body:[{host:'current.example.test',origin:'https://current.example.test',kind:'canonical',relying_party_identifier:'current.example.test',valid:true}]}
 })
 await router.push('/t/system/settings/relying-party-ids');await flushPromises();await router.push('/t/acme/settings/relying-party-ids');await flushPromises()
 finish({status:200,body:[{host:'stale.example.test',kind:'canonical',relying_party_identifier:'stale.example.test',valid:true}]});await flushPromises()
 expect(wrapper.text()).toContain('current.example.test');expect(wrapper.text()).not.toContain('stale.example.test');wrapper.unmount()
})
it('opens the prerequisite link on the destination settings tab',async()=>{
 const {default:Connections}=await import('./connections/Detail.vue')
 const {wrapper}=await mountAt(Connections,'/t/acme/connections/db?tab=password',c=>c.url.endsWith('passkey-prerequisites')?respond(c):{status:200,body:connection('db')})
 expect(wrapper.find('#passkey-enabled').exists()).toBe(true);wrapper.unmount()
})
it('keeps passkey policy out of the unrestricted stored JSON controls and lets passwords satisfy prerequisites',async()=>{
 const {default:ConnectionSettings}=await import('./connections/SettingsTab.vue')
 const settingsPage=defineComponent({render:()=>h(ConnectionSettings,{tenant:tenant('acme'),connection:connection('db')})})
 const s=await mountAt(settingsPage,'/t/acme/connections/db',respond)
 expect(s.wrapper.find('#stored-authentication_methods').exists()).toBe(false);expect(s.wrapper.find('#stored-passkey_options').exists()).toBe(false);s.wrapper.unmount()
 const passwordPage=defineComponent({render:()=>h(PasswordTab,{tenant:tenant('acme'),connection:connection('db',{options:{authentication_methods:{password:{enabled:false},passkey:{enabled:true}},password_options:{}}})})})
 const p=await mountAt(passwordPage,'/t/acme/connections/db',respond)
 await p.wrapper.get('#password-enabled').setValue(true);await p.wrapper.get('#password-settings').trigger('submit');await flushPromises()
 expect((p.calls.find(c=>c.method==='PATCH')?.body as {options:{authentication_methods:unknown}}).options.authentication_methods).toEqual({password:{enabled:true},passkey:{enabled:true}});p.wrapper.unmount()
})
it('drops an application settings save after route navigation even before client props change',async()=>{
 let finish!:(r:Reply)=>void
 const page=defineComponent({render:()=>h(SettingsTab,{tenant:tenant('acme'),client:client('app')})})
 const {wrapper,router}=await mountAt(page,'/t/acme/applications/app',c=>c.method==='PATCH'?new Promise(r=>{finish=r}):respond(c))
 await wrapper.get('#app-passkey-grant').setValue(true);await wrapper.get('form').trigger('submit');await flushPromises()
 await router.push('/t/acme/applications/other');await flushPromises();finish({status:200,body:client('app')});await flushPromises()
 expect(wrapper.text()).not.toContain('Saved');wrapper.unmount()
})
it('does not rewrite untouched mobile platform objects while saving an application name',async()=>{
 const app=client('app',{mobile:{ios:{team_id:'TEAM'}}})
 const page=defineComponent({render:()=>h(SettingsTab,{tenant:tenant('acme'),client:app})})
 const {wrapper,calls}=await mountAt(page,'/t/acme/applications/app',respond)
 await wrapper.get('#app-name').setValue('Renamed app');await wrapper.get('form').trigger('submit');await flushPromises()
 expect(calls.find(c=>c.method==='PATCH')?.body).not.toHaveProperty('mobile');wrapper.unmount()
})
