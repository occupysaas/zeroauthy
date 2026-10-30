import { watch } from 'vue'
import { useRoute } from 'vue-router'

// onModalClosed reloads a list when a create or edit modal shown over it
// (a child route) closes, so what the modal changed shows at once.
export function onModalClosed(reload: () => unknown): void {
  const route = useRoute()
  watch(
    () => route.matched.length,
    (n, old) => {
      if (n < old) void reload()
    },
  )
}
