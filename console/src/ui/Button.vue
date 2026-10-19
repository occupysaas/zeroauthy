<script setup lang="ts">
withDefaults(
  defineProps<{
    variant?: 'primary' | 'secondary' | 'danger' | 'ghost'
    type?: 'button' | 'submit'
    disabled?: boolean
  }>(),
  { variant: 'secondary', type: 'button', disabled: false },
)

const variants = {
  primary: 'border-accent bg-accent text-accent-text hover:border-accent-hover hover:bg-accent-hover',
  secondary: 'border-rule bg-surface text-text hover:bg-active',
  danger: 'border-danger bg-danger text-surface hover:opacity-90',
  ghost: 'border-transparent bg-transparent text-text hover:bg-active',
}
const disabledClass = 'cursor-not-allowed border-disabled bg-disabled text-disabled-text'
</script>

<template>
  <button
    :type="type"
    :class="['cursor-pointer rounded border px-3.5 py-1.5 font-sans font-bold', disabled ? disabledClass : variants[variant]]"
    :disabled="disabled"
  >
    <slot />
  </button>
</template>
