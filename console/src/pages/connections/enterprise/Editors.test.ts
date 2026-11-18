import { mount, flushPromises, DOMWrapper } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { servicesKey } from '../../../context'
import { fakeServices, connection, tenant, type Call, type Reply } from '../../../test/services'
import Settings from './Settings.vue'
import Mapping from './Mapping.vue'
import Keys from './Keys.vue'
import LoginExperience from './LoginExperience.vue'
import type { Component } from 'vue'

const item=connection('con_oidc',{name:'corp',strategy:'oidc',options:{type:'back_channel',client_id:'client',scope:'openid',discovery_url:'https://idp.example/discovery',tenant_domain:'corp.example'}})
async function editor(component:Component,handler:(c:Call)=>Reply|Promise<Reply>=()=>({status:200,body:item})){
 const {services,calls,pinia,i18n}=fakeServices(handler)
 const wrapper=mount(component,{props:{tenant:tenant('acme'),connection:item},attachTo:document.body,global:{plugins:[pinia,i18n],provide:{[servicesKey as symbol]:services}}})
 await flushPromises();return {wrapper,calls}
}
describe('Enterprise connection editors',()=>{
 it('marks weaker PKCE and preserves unedited options without a secret',async()=>{
  const {wrapper,calls}=await editor(Settings)
  await wrapper.find('#enterprise-pkce').setValue('plain')
  expect(wrapper.text().toLowerCase()).toContain('weaker')
  expect(wrapper.find('[data-testid="not-enforced"]').exists()).toBe(true)
  await wrapper.find('form').trigger('submit');await flushPromises()
  const options=(calls.find(c=>c.method==='PATCH')?.body as {options:Record<string,unknown>}).options
  expect(options.connection_settings).toEqual({pkce:'plain'});expect(options.tenant_domain).toBe('corp.example');expect(options).not.toHaveProperty('client_secret');wrapper.unmount()
 })
 it('refuses restricted mapping targets before writing, and saves a valid map',async()=>{
  const {wrapper,calls}=await editor(Mapping)
  await wrapper.find('#enterprise-mapping-mode').setValue('use_map')
  await wrapper.find('#enterprise-mapping').setValue('{"blocked":"true"}')
  await wrapper.find('form').trigger('submit');expect(calls.filter(c=>c.method==='PATCH')).toHaveLength(0)
  expect(wrapper.text().toLowerCase()).toContain('reserved')
  await wrapper.find('#enterprise-mapping').setValue('{"name":"${context.tokenset.name}"}')
  await wrapper.find('form').trigger('submit');await flushPromises()
  expect((calls.find(c=>c.method==='PATCH')?.body as {options:Record<string,unknown>}).options.attribute_map).toMatchObject({mapping_mode:'use_map',attributes:{name:'${context.tokenset.name}'}});wrapper.unmount()
 })
 it('saves login domains and button settings',async()=>{
  const {wrapper,calls}=await editor(LoginExperience)
  await wrapper.find('#enterprise-domains').setValue('CORP.EXAMPLE\ncorp.example\nother.example')
  await wrapper.find('form').trigger('submit');await flushPromises()
  expect((calls.find(c=>c.method==='PATCH')?.body as {options:Record<string,unknown>}).options.domain_aliases).toEqual(['corp.example','other.example']);wrapper.unmount()
 })
 it('creates keys and requires confirmation before rotation',async()=>{
  const key={kid:'current',cert:'public cert',fingerprint:'AA',thumbprint:'AA',key_use:'signing',algorithm:'RS256',current:true}
  const {wrapper,calls}=await editor(Keys,c=>({status:c.method==='POST'?201:200,body:c.url.endsWith('/rotate')?key:[key]}))
  await wrapper.find('[data-testid="create-keys"]').trigger('click');await flushPromises()
  expect(calls.some(c=>c.method==='POST'&&c.url.endsWith('/keys'))).toBe(true)
  await wrapper.find('[data-testid="rotate-keys"]').trigger('click');await flushPromises()
  expect(calls.some(c=>c.url.endsWith('/rotate'))).toBe(false)
  const dialog=new DOMWrapper(document.querySelector('[role="dialog"]')!)
  await dialog.find('form').trigger('submit');await flushPromises()
  expect(calls.some(c=>c.method==='POST'&&c.url.endsWith('/rotate'))).toBe(true);wrapper.unmount()
 })
 it('ignores a keys response from the previous connection',async()=>{
  let release!:(r:Reply)=>void
  const {wrapper}=await editor(Keys,c=>c.url.includes('con_oidc')?new Promise<Reply>(r=>{release=r}):{status:200,body:[]})
  await wrapper.setProps({connection:connection('con_other',{strategy:'oidc'})});await flushPromises()
  release({status:200,body:[{kid:'stale-key',cert:'stale-cert',fingerprint:'AA',thumbprint:'AA'}]});await flushPromises()
  expect(wrapper.text()).not.toContain('stale-key');wrapper.unmount()
 })
})
