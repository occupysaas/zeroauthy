import { expectTypeOf, it } from 'vitest'
import type { UserRefreshToken } from './client'
import type { components } from './schema'

it('preserves required refresh-token fields and optional device and nullable timestamps', () => {
  type RequiredKeys<T> = { [K in keyof T]-?: object extends Pick<T, K> ? never : K }[keyof T]
  expectTypeOf<RequiredKeys<UserRefreshToken>>().toEqualTypeOf<'id' | 'user_id' | 'created_at' | 'idle_expires_at' | 'expires_at' | 'client_id' | 'session_id' | 'rotating' | 'resource_servers' | 'last_exchanged_at'>()
  expectTypeOf<UserRefreshToken['last_exchanged_at']>().toEqualTypeOf<string | null>()
  expectTypeOf<UserRefreshToken['expires_at']>().toEqualTypeOf<string | null>()
  expectTypeOf<UserRefreshToken['idle_expires_at']>().toEqualTypeOf<string | null>()
  expectTypeOf<UserRefreshToken['session_id']>().toEqualTypeOf<string | null>()
  expectTypeOf<UserRefreshToken['device']>().toEqualTypeOf<components['schemas']['RefreshTokenDevice'] | undefined>()
  expectTypeOf<UserRefreshToken['refresh_token_metadata']>().toEqualTypeOf<Record<string, string> | null | undefined>()
})
