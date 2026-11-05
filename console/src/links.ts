// Constants the console shows or links to that are not translated: the
// product name and where its documentation and source live.

export const product = 'zeroauthy'
// The brand is drawn in two colours; these are its two parts.
export const productParts = ['zero', 'authy'] as const
export const docsURL = 'https://github.com/occupysaas/zeroauthy/tree/main/docs'
export const sourceURL = 'https://github.com/occupysaas/zeroauthy'

// Links on the Home page; titleKey is a catalog key.
export const homeLinks: { titleKey: string; href: string }[] = [
  { titleKey: 'docLinks.managementAPI', href: 'https://github.com/occupysaas/zeroauthy/blob/main/docs/management-api.md' },
  { titleKey: 'docLinks.console', href: 'https://github.com/occupysaas/zeroauthy/blob/main/docs/console.md' },
  { titleKey: 'docLinks.compat', href: 'https://github.com/occupysaas/zeroauthy/blob/main/docs/compat/matrix.md' },
]

// The query guide the users search box links to.
export const userSearchDocsURL = 'https://github.com/occupysaas/zeroauthy/blob/main/docs/user-search.md'
