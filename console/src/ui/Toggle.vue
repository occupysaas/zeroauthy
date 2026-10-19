<script setup lang="ts">
import { SwitchRoot, SwitchThumb } from 'reka-ui'

// A labelled on/off switch.
withDefaults(defineProps<{ label: string; modelValue?: boolean; disabled?: boolean }>(), { modelValue: false, disabled: false })
defineEmits<{ 'update:modelValue': [boolean] }>()
</script>

<template>
  <label :class="['inline-flex items-center gap-2', disabled ? 'cursor-not-allowed text-disabled-text' : 'cursor-pointer']">
    <SwitchRoot
      :model-value="modelValue"
      :disabled="disabled"
      class="relative h-5 w-9 rounded-full border border-rule bg-surface data-[state=checked]:bg-accent data-[disabled]:cursor-not-allowed data-[disabled]:bg-disabled"
      @update:model-value="$emit('update:modelValue', $event)"
    >
      <SwitchThumb class="block h-3.5 w-3.5 translate-x-0.5 rounded-full bg-text transition-transform data-[state=checked]:translate-x-4 data-[state=checked]:bg-accent-text" />
    </SwitchRoot>
    {{ label }}
  </label>
</template>
