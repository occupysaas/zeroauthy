import { expect, it } from 'vitest'
import { metadataValue, validName } from './context'
it.each(['', 'UPPER', '-start', 'a.b', 'a'.repeat(51)])('rejects invalid organization name %s', name => { expect(validName(name)).toBe(false) })
it('accepts bounded organization names', () => { expect(validName('a_9-z')).toBe(true); expect(validName('a'.repeat(50))).toBe(true) })
it.each(['null', '[]', '{"team":null}', '{"team":""}', '{"bad-key":"a"}', JSON.stringify({ ['a'.repeat(51)]: 'a' }), JSON.stringify({ a: 'b'.repeat(256) }), JSON.stringify(Object.fromEntries(Array.from({ length: 26 }, (_, i) => ['a' + i, 'a'])))])('rejects invalid metadata %s', input => { expect(metadataValue(input)).toBeUndefined() })
it('accepts an empty metadata object and all upper boundaries', () => {
  expect(metadataValue('{}')).toEqual({})
  const value = Object.fromEntries(Array.from({ length: 25 }, (_, i) => ['a'.repeat(48) + String(i).padStart(2, '0'), 'x'.repeat(255)]))
  expect(metadataValue(JSON.stringify(value))).toEqual(value)
})
