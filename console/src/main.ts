import { createPinia } from 'pinia'
import { createApp } from 'vue'
import { Api } from './api/client'
import App from './App.vue'
import { Auth } from './auth/auth'
import { servicesKey, type Services } from './context'
import { applyLocale, createConsoleI18n, savedLocale } from './i18n'
import { createConsoleRouter } from './router'
import { useSessionStore } from './stores/session'
import { applyTheme, savedTheme } from './theme'
import './ui/base.css'

applyTheme(savedTheme())

const origin = window.location.origin
const auth = new Auth({ origin })
const api = new Api(origin, () => auth.accessToken())
const services: Services = { auth, api }

const locale = savedLocale()
const i18n = createConsoleI18n(locale)
applyLocale(i18n, locale)

const pinia = createPinia()
const app = createApp(App).use(pinia).use(i18n)
useSessionStore().attach(auth.user)
app.provide(servicesKey, services).use(createConsoleRouter(services)).mount('#app')
