import type { EmailTemplateName } from '../../api/client'

export const emailTemplateNames = [
  'verify_email', 'verify_email_by_code', 'auth_email_by_code', 'reset_email', 'reset_email_by_code', 'welcome_email',
  'blocked_account', 'stolen_credentials', 'enrollment_email', 'mfa_oob_code', 'user_invitation', 'async_approval', 'change_password', 'password_reset',
] as const satisfies readonly EmailTemplateName[]
