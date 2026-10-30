import { ref, type Ref } from 'vue'

export interface Confirm {
  open: Ref<boolean>
  message: Ref<string>
  label: Ref<string>
  ask(message: string, label: string): Promise<boolean>
  answer(ok: boolean): void
  closed(): void
}

// useConfirm asks before something consequential in a ConfirmPrompt modal,
// answering true only when the operator presses the confirm button. The
// answer comes once the modal has closed, so focus is back on the page
// before the action runs.
export function useConfirm(): Confirm {
  const open = ref(false)
  const message = ref('')
  const label = ref('')
  let settle: ((ok: boolean) => void) | undefined
  let answered = false
  function answer(ok: boolean) {
    answered = ok
    open.value = false
  }
  function closed() {
    const s = settle
    settle = undefined
    s?.(answered)
  }
  function ask(m: string, l: string): Promise<boolean> {
    settle?.(false)
    answered = false
    message.value = m
    label.value = l
    open.value = true
    return new Promise((resolve) => (settle = resolve))
  }
  return { open, message, label, ask, answer, closed }
}
