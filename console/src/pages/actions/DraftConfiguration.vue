<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import type { ActionDependency, ActionSecretInput } from '../../api/client'
import Button from '../../ui/Button.vue'
import Field from '../../ui/Field.vue'
const dependencies = defineModel<ActionDependency[]>('dependencies', { required: true })
const secrets = defineModel<ActionSecretInput[]>('secrets', { required: true })
const { t } = useI18n()
</script>
<template>
          <section class="card stack" :aria-label="t('actions.dependencies')">
            <h2>{{ t('actions.dependencies') }}</h2><p id="dependency-hint" class="muted">{{ t('actions.dependencyHint') }}</p>
            <div v-for="(d, i) in dependencies" :key="i" class="row flex-wrap">
              <Field :id="'dependency-name-' + i" :label="t('actions.packageName')"><input :id="'dependency-name-' + i" v-model="d.name" aria-describedby="dependency-hint" /></Field>
              <Field :id="'dependency-version-' + i" :label="t('actions.version')"><input :id="'dependency-version-' + i" v-model="d.version" aria-describedby="dependency-hint" /></Field>
              <Button @click="dependencies.splice(i, 1)">{{ t('actions.removeDependency') }}</Button>
            </div>
            <Button :disabled="dependencies.length >= 50" @click="dependencies.push({ name: '', version: '' })">{{ t('actions.addDependency') }}</Button>
          </section>
          <section class="card stack" :aria-label="t('actions.secrets')">
            <h2>{{ t('actions.secrets') }}</h2><p id="secrets-hint" class="muted">{{ t('actions.secretHint') }}</p>
            <div v-for="(s, i) in secrets" :key="i" class="row flex-wrap">
              <Field :id="'secret-name-' + i" :label="t('actions.secretName')"><input :id="'secret-name-' + i" v-model="s.name" aria-describedby="secrets-hint" /></Field>
              <Field :id="'secret-value-' + i" :label="t('actions.secretValue')"><input :id="'secret-value-' + i" :value="s.value ?? ''" type="password" autocomplete="new-password" aria-describedby="secrets-hint" @input="s.value = ($event.target as HTMLInputElement).value" /></Field>
              <Button @click="secrets.splice(i, 1)">{{ t('actions.removeSecret') }}</Button>
            </div>
            <Button :disabled="secrets.length >= 64" @click="secrets.push({ name: '', value: '' })">{{ t('actions.addSecret') }}</Button>
          </section>
</template>
