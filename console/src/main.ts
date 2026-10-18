import { createApp } from 'vue'
import { Api } from './api/client'
import App from './App.vue'
import { Auth } from './auth/auth'
import { servicesKey, type Services } from './context'
import { createConsoleRouter } from './router'
import { Tenants } from './tenants'
import { applyTheme, savedTheme } from './theme'
import './ui/base.css'

applyTheme(savedTheme())

const origin = window.location.origin
const auth = new Auth({ origin })
const api = new Api(origin, () => auth.accessToken())
const services: Services = { auth, api, tenants: new Tenants(api) }

createApp(App).provide(servicesKey, services).use(createConsoleRouter(services)).mount('#app')
