<script setup lang="ts">
import { computed, useId } from 'vue'
import { SwitchRoot, SwitchThumb } from 'reka-ui'

// A labelled on/off switch.
const generatedId = useId()
const props = withDefaults(defineProps<{ id?: string; label: string; modelValue?: boolean; disabled?: boolean; invalid?: boolean; describedBy?: string }>(), { modelValue: false, disabled: false })
const controlId = computed(() => props.id ?? generatedId)
defineEmits<{ 'update:modelValue': [boolean] }>()
</script>

<template>
  <span :class="['inline-flex items-center gap-2', disabled ? 'cursor-not-allowed text-disabled-text' : 'cursor-pointer']">
    <SwitchRoot
      :id="controlId"
      :aria-invalid="invalid"
      :aria-describedby="describedBy"
      :model-value="modelValue"
      :disabled="disabled"
      class="relative h-5 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus w-9 rounded-full border border-rule bg-surface data-[state=checked]:bg-accent data-[disabled]:cursor-not-allowed data-[disabled]:bg-disabled"
      @update:model-value="$emit('update:modelValue', $event)"
    >
      <SwitchThumb class="block h-3.5 w-3.5 translate-x-0.5 rounded-full bg-text transition-transform data-[state=checked]:translate-x-4 data-[state=checked]:bg-accent-text" />
    </SwitchRoot>
    <label :for="controlId" :class="disabled ? 'cursor-not-allowed' : 'cursor-pointer'">{{ label }}</label>
  </span>
</template>
