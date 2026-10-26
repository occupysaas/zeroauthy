<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import type { CustomDomain } from '../../api/client'
import CopyButton from '../../ui/CopyButton.vue'

const props = defineProps<{ domain: CustomDomain }>()
const { t } = useI18n()
const txt = computed(() => props.domain.verification?.methods?.[0])
</script>

<template>
  <section aria-labelledby="dns-title">
    <h2 id="dns-title">{{ t('customDomain.dnsTitle') }}</h2>
    <template v-if="txt">
      <p>{{ t('customDomain.dnsTxt') }}</p>
      <dl>
        <dt>{{ t('customDomain.dnsName') }}</dt>
        <dd><code>{{ txt.domain }}</code> <CopyButton :value="txt.domain ?? ''" /></dd>
        <dt>{{ t('customDomain.dnsValue') }}</dt>
        <dd><code class="break-all">{{ txt.record }}</code> <CopyButton :value="txt.record ?? ''" /></dd>
      </dl>
    </template>
    <p v-if="domain.origin_domain_name">
      {{ domain.type === 'self_managed_certs' ? t('customDomain.dnsProxy', { target: domain.origin_domain_name }) : t('customDomain.dnsManaged', { target: domain.origin_domain_name }) }}
    </p>
  </section>
</template>
