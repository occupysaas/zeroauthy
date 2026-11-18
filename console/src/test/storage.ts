// Web Storage keys the console itself wrote. vue-router 5 saves scroll
// positions under "vue-router:scroll" in sessionStorage; that holds only
// offsets, so privacy checks ignore it.
const ROUTER_KEYS = new Set(['vue-router:scroll'])

export function appStorageKeys(): string[] {
  const keys: string[] = []
  for (const s of [window.localStorage, window.sessionStorage]) {
    for (let i = 0; i < s.length; i++) {
      const k = s.key(i)
      if (k !== null && !ROUTER_KEYS.has(k)) keys.push(k)
    }
  }
  return keys
}
