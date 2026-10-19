<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { errorMessage, useServices } from '../context'
import { useI18n } from 'vue-i18n'
import Banner from '../ui/Banner.vue'
import Button from '../ui/Button.vue'

const { t } = useI18n()

const { auth } = useServices()
const router = useRouter()
const error = ref('')

onMounted(async () => {
  try {
    const next = await auth.handleCallback(window.location.search)
    if (next !== null) await router.replace(next)
  } catch (e) {
    error.value = errorMessage(e)
  }
})
</script>

<template>
  <main class="mx-auto my-[15vh] max-w-lg p-4">
    <template v-if="error">
      <h1>{{ t('signInFailed') }}</h1>
      <Banner kind="error">{{ error }}</Banner>
      <Button variant="primary" @click="auth.login('/', false)">{{ t('signInAgain') }}</Button>
    </template>
    <p v-else class="muted" role="status">{{ t('signingIn') }}</p>
  </main>
</template>
