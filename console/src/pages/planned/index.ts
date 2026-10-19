import type { Component } from 'vue'
import { isPlanned, sections } from '../../layout/sections'
import Placeholder from './Placeholder.vue'

/** The page behind each planned route, by section key. */
export const plannedPages: Record<string, Component> = Object.fromEntries(
  sections.filter(isPlanned).map((s) => [s.key, Placeholder]),
)
