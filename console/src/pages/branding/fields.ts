// Frozen Plan 22 theme field inventory.
export const themeFields = [
  {
    "path": "borders.button_border_radius",
    "state": "effective"
  },
  {
    "path": "borders.button_border_weight",
    "state": "effective"
  },
  {
    "path": "borders.buttons_style",
    "state": "effective"
  },
  {
    "path": "borders.input_border_radius",
    "state": "effective"
  },
  {
    "path": "borders.input_border_weight",
    "state": "effective"
  },
  {
    "path": "borders.inputs_style",
    "state": "effective"
  },
  {
    "path": "borders.show_widget_shadow",
    "state": "effective"
  },
  {
    "path": "borders.widget_border_weight",
    "state": "effective"
  },
  {
    "path": "borders.widget_corner_radius",
    "state": "effective"
  },
  {
    "path": "colors.body_text",
    "state": "effective"
  },
  {
    "path": "colors.error",
    "state": "effective"
  },
  {
    "path": "colors.header",
    "state": "effective"
  },
  {
    "path": "colors.icons",
    "state": "effective"
  },
  {
    "path": "colors.input_background",
    "state": "effective"
  },
  {
    "path": "colors.input_border",
    "state": "effective"
  },
  {
    "path": "colors.input_filled_text",
    "state": "effective"
  },
  {
    "path": "colors.input_labels_placeholders",
    "state": "effective"
  },
  {
    "path": "colors.links_focused_components",
    "state": "effective"
  },
  {
    "path": "colors.primary_button",
    "state": "effective"
  },
  {
    "path": "colors.primary_button_label",
    "state": "effective"
  },
  {
    "path": "colors.secondary_button_border",
    "state": "effective"
  },
  {
    "path": "colors.secondary_button_label",
    "state": "effective"
  },
  {
    "path": "colors.success",
    "state": "effective"
  },
  {
    "path": "colors.widget_background",
    "state": "effective"
  },
  {
    "path": "colors.widget_border",
    "state": "effective"
  },
  {
    "path": "fonts.body_text",
    "state": "effective"
  },
  {
    "path": "fonts.buttons_text",
    "state": "effective"
  },
  {
    "path": "fonts.font_url",
    "state": "effective"
  },
  {
    "path": "fonts.input_labels",
    "state": "effective"
  },
  {
    "path": "fonts.links",
    "state": "effective"
  },
  {
    "path": "fonts.links_style",
    "state": "effective"
  },
  {
    "path": "fonts.reference_text_size",
    "state": "effective"
  },
  {
    "path": "fonts.subtitle",
    "state": "effective"
  },
  {
    "path": "fonts.title",
    "state": "effective"
  },
  {
    "path": "page_background.background_color",
    "state": "effective"
  },
  {
    "path": "page_background.background_image_url",
    "state": "effective"
  },
  {
    "path": "page_background.page_layout",
    "state": "effective"
  },
  {
    "path": "widget.header_text_alignment",
    "state": "effective"
  },
  {
    "path": "widget.logo_height",
    "state": "effective"
  },
  {
    "path": "widget.logo_position",
    "state": "effective"
  },
  {
    "path": "widget.logo_url",
    "state": "effective"
  },
  {
    "path": "widget.social_buttons_layout",
    "state": "stored_only"
  }
] as const

export type ThemeField = { path: string; kind: string; options?: string[]; min?: number; max?: number }
export const activeThemeFields: ThemeField[] = [
  {
    "path": "borders.button_border_radius",
    "kind": "number",
    "min": 0,
    "max": 64
  },
  {
    "path": "borders.button_border_weight",
    "kind": "number",
    "min": 0,
    "max": 64
  },
  {
    "path": "borders.buttons_style",
    "kind": "select",
    "options": [
      "pill",
      "rounded",
      "sharp"
    ]
  },
  {
    "path": "borders.input_border_radius",
    "kind": "number",
    "min": 0,
    "max": 64
  },
  {
    "path": "borders.input_border_weight",
    "kind": "number",
    "min": 0,
    "max": 64
  },
  {
    "path": "borders.inputs_style",
    "kind": "select",
    "options": [
      "pill",
      "rounded",
      "sharp"
    ]
  },
  {
    "path": "borders.show_widget_shadow",
    "kind": "boolean"
  },
  {
    "path": "borders.widget_border_weight",
    "kind": "number",
    "min": 0,
    "max": 64
  },
  {
    "path": "borders.widget_corner_radius",
    "kind": "number",
    "min": 0,
    "max": 64
  },
  {
    "path": "colors.body_text",
    "kind": "color"
  },
  {
    "path": "colors.error",
    "kind": "color"
  },
  {
    "path": "colors.header",
    "kind": "color"
  },
  {
    "path": "colors.icons",
    "kind": "color"
  },
  {
    "path": "colors.input_background",
    "kind": "color"
  },
  {
    "path": "colors.input_border",
    "kind": "color"
  },
  {
    "path": "colors.input_filled_text",
    "kind": "color"
  },
  {
    "path": "colors.input_labels_placeholders",
    "kind": "color"
  },
  {
    "path": "colors.links_focused_components",
    "kind": "color"
  },
  {
    "path": "colors.primary_button",
    "kind": "color"
  },
  {
    "path": "colors.primary_button_label",
    "kind": "color"
  },
  {
    "path": "colors.secondary_button_border",
    "kind": "color"
  },
  {
    "path": "colors.secondary_button_label",
    "kind": "color"
  },
  {
    "path": "colors.success",
    "kind": "color"
  },
  {
    "path": "colors.widget_background",
    "kind": "color"
  },
  {
    "path": "colors.widget_border",
    "kind": "color"
  },
  {
    "path": "fonts.body_text.size",
    "kind": "number",
    "min": 50,
    "max": 300
  },
  {
    "path": "fonts.body_text.bold",
    "kind": "boolean"
  },
  {
    "path": "fonts.buttons_text.size",
    "kind": "number",
    "min": 50,
    "max": 300
  },
  {
    "path": "fonts.buttons_text.bold",
    "kind": "boolean"
  },
  {
    "path": "fonts.font_url",
    "kind": "text"
  },
  {
    "path": "fonts.input_labels.size",
    "kind": "number",
    "min": 50,
    "max": 300
  },
  {
    "path": "fonts.input_labels.bold",
    "kind": "boolean"
  },
  {
    "path": "fonts.links.size",
    "kind": "number",
    "min": 50,
    "max": 300
  },
  {
    "path": "fonts.links.bold",
    "kind": "boolean"
  },
  {
    "path": "fonts.links_style",
    "kind": "select",
    "options": [
      "normal",
      "underlined"
    ]
  },
  {
    "path": "fonts.reference_text_size",
    "kind": "number",
    "min": 12,
    "max": 24
  },
  {
    "path": "fonts.subtitle.size",
    "kind": "number",
    "min": 50,
    "max": 300
  },
  {
    "path": "fonts.subtitle.bold",
    "kind": "boolean"
  },
  {
    "path": "fonts.title.size",
    "kind": "number",
    "min": 50,
    "max": 300
  },
  {
    "path": "fonts.title.bold",
    "kind": "boolean"
  },
  {
    "path": "page_background.background_color",
    "kind": "color"
  },
  {
    "path": "page_background.background_image_url",
    "kind": "text"
  },
  {
    "path": "page_background.page_layout",
    "kind": "select",
    "options": [
      "center",
      "left",
      "right"
    ]
  },
  {
    "path": "widget.header_text_alignment",
    "kind": "select",
    "options": [
      "center",
      "left",
      "right"
    ]
  },
  {
    "path": "widget.logo_height",
    "kind": "number",
    "min": 0,
    "max": 200
  },
  {
    "path": "widget.logo_position",
    "kind": "select",
    "options": [
      "center",
      "left",
      "right",
      "none"
    ]
  },
  {
    "path": "widget.logo_url",
    "kind": "text"
  }
]

export const textPrompts = ["login", "login-id", "login-password", "login-passwordless", "login-email-verification", "signup", "signup-id", "signup-password", "phone-identifier-enrollment", "phone-identifier-challenge", "email-identifier-challenge", "reset-password", "custom-form", "consent", "customized-consent", "logout", "mfa-push", "mfa-otp", "mfa-voice", "mfa-phone", "mfa-webauthn", "mfa-sms", "mfa-email", "mfa-recovery-code", "mfa", "status", "device-flow", "email-verification", "email-otp-challenge", "organizations", "invitation", "common", "captcha", "passkeys", "brute-force-protection", "zeroauthy"] as const
