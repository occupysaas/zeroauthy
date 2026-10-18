# zeroauthy — Management UI: maintainer review notes

- **Status:** Notes (input for the sub-project 3 brainstorm, not a design)
- **Date:** 2026-10-17
- **Author:** the maintainer, who reviewed the management dashboard of a tenant they own
- **Related:** core spec §7.1 and the admin console row of the stack table (Vue 3 SPA served under `/admin`, talking only to the Management API).

## Clean-room note

These notes are the maintainer's own summary of the features and their grouping, written in the maintainer's own words with most descriptions left out. They are a scope inventory, not a capture: no screenshots, DOM, assets or copied text. Integration and provider names are listed as facts.

When the console is designed, its layout, visuals and all text must be original (CLEAN_ROOM.md "Prohibited": no copying of UI templates, stylesheets, images or product copy). Each feature below must also be backed by the public docs or the Management API before it is built.

## Header

- **Left:** logo, then the tenant selector (drop-down).
- **Right:** documentation link, link to the GitHub source, notifications, language, and the account menu (drop-down).

## Sidebar

Home · Activity · Applications · Authentication · Organizations · User Management · Branding · Security · Actions · Event Streams · Monitoring · Marketplace · Extensions · Settings.

Sections marked *(group)* below expand and collapse.

### Home

A dashboard with basic information and links to the documentation, the SDKs and getting-started guides.

### Activity

A login graph, plus totals for users, applications, APIs and connections.

### Applications *(group)*

#### Applications

- A list of applications and a "create application" button.
- New applications can be Native, SPA, regular web or machine-to-machine, each with a name.
- There is an option to mark an application as third-party owned, with stricter security.
- An application can also be imported from a metadata URL (see https://auth0.com/docs/get-started/auth0-overview/create-applications).

#### APIs

- The list includes system APIs (the account API and the organization API) as well as the tenant's own APIs.
- Creating an API asks for:
  - a name and an identifier;
  - a JWT profile and a signing algorithm;
  - user-delegated access: all apps, per app, or no apps;
  - client access: per app or no apps.

#### SSO Integrations

A large catalogue of ready-made SSO integrations with third-party products, such as Shutterstock, Adobe Sign, AD RMS, Aha!, Airbrake, AlertOps, anecdotes, AnyPoint, AppDynamics, ASP.NET SSO, AssetSonar, Atatus, atSpoke, Automox, Axomo, BambooHR, Blissbook, Blocks Edit, Blogin, Bonusly, Box, BreezyHR, Brightfunds, Bugsnag, Buildkite, Carbonite, Celonis, Chargebee, Cisco Umbrella, Cisco WebEx, CloudAMQP, CloudBees, Cloudentity, cloudtamer.io, CoderPad, Coggle, Concur, ContractSafe, Coralogix, Databox, Datadog, Dell Boomi, Deputy, Deskpro, Dmarcian, Domo, Dropbox, Dynamics CRM, Egencia, Egnyte, Ekarda, Eloqua, Envoy, Evernote Business, EZOfficeInventory, EZRentOut, Fastly, Federated Directory, Feroot, Fivetran, Freshdesk, Freshservice, GitHub Enterprise, Google Workspace, Harness, Helper Helper, Heroku, Hosted Graphite, Hub Planner, Humanity, jamf Pro, Jenkins, Jitbit Helpdesk, Jostle, Kintone, Klipfolio, KnowBe4, LeanKit, Litmos, Lucidchart, Mapbox, MongoDB Cloud, New Relic, Nuclino, Office 365, onDMARC, OneDesk, Orginio, PagerDuty, ParkMyCloud, People HR, Phrase, Pingboard, Pluralsight, PolicyTech, Productive, PurelyHR, Quickbase, Reftab, Roadmunk, Rockset, Rootly, Salesforce, Sauce Labs, ScreenSteps, SecureFlag, Sentry, ShareFile, SharePoint, Shufflrr, Sketchboard, Slack, Slemma, SolarWinds AppOptics and other SolarWinds products, SonarQube, SpringCM, Sprout Video, Status Hero, Statushub, Sumo Logic, Tableau Online, Tableau Server, TelemetryTV, Textmagic, ThousandEyes, Thycotic Secret Server, UserEcho, Visual Paradigm, Way We Do, Weekdone, WhosOff, WhosOffice, Workday, WorkOS, Workpath, Workplace, Workteam, Wrike, Yodeck, Zendesk and Zoom.

### Authentication *(group)*

#### Database

- Create database connections.
- Identifiers: email address (with an option to allow non-unique emails), phone number, username.
- Authentication methods: password, passkey.
- Disable sign-ups.
- Promote the connection to domain level.

#### Social

Create social connections. Providers seen:
- Klarna, dAccount, Exact, Evernote (sandbox and production), Planning Center, Yammer, Dwolla, WordPress, Shopify
- Weibo, RenRen, Baidu, Yandex, VKontakte, KakaoTalk Login, Line
- Fitbit, Salesforce (Community, sandbox, production), Box, Basecamp, Yahoo, Amazon, Twitter, PayPal (sandbox and production), Bitbucket, Dropbox
- GitHub, LinkedIn, Microsoft, Apple, Facebook, Google
- Shop, AgentID, Indeed, monday.com, Revolut ID, Sign in with Slack, Slack OAuth 2.0, Snapchat, Tumblr
- 1Kosmos BlockID, Asignio, Badge, BitBadges, Didit, DigitalOcean, Discord, Dock Web3 ID, Dribbble, Figma, FreshBooks, Hugging Face
- ID.me (community and identity), IDPartner, Imgur, Iuncta, netID, Okta Personal, Photolok MFA IdP
- QuickBooks Online, Spotify, Stripe Connect, Twitch, Unstoppable Domains, Vimeo, Vipps MobilePay, Vula Labs

#### Enterprise

- SAML.
- OpenID Connect.
- Provider-specific connections: Okta Workforce Identity Cloud, Google Workspace, Microsoft Entra ID, ADFS, Active Directory / LDAP, PingFederate.

#### Passwordless

SMS and email.

#### Custom Token Exchange

Accepts tokens issued elsewhere and exchanges them for tenant tokens, with the logic written as Actions.

#### Authentication Profile

Three login styles: identifier and password on one screen; identifier first; identifier first with biometrics (enterprise).

### Organizations

- Configure an application for use with organizations.
- Create organizations.

### User Management *(group)*

#### Users

- Create a user (pick a connection, then email and password).
- Import users.

#### Enterprise Groups

Sync groups from enterprise directories (probably LDAP and similar systems).

#### Roles

Tenant-defined roles, each with a name and a description.

### Branding *(group)*

#### Universal Login

- Edit the branding theme.
- Edit text and translations.
- Customize screens with partials.
- Build fully custom screens.
- Core configuration.

#### Custom Domains

Not reviewed.

#### Email Templates

Editable templates:
- verification email (link and code)
- welcome email
- MFA enrollment
- change password (link and code)
- blocked account
- password breach alert
- email MFA verification code
- user invitation

#### Email Provider

Either the built-in provider or one of: Resend, Mandrill, Amazon SES, Azure Communication Services, Microsoft 365, SendGrid, SparkPost, Mailgun, or a custom SMTP server.

#### Phone Templates

Message wording for: blocked account, change password, one-time password for verification, and one-time password at account creation.

#### Phone Provider

Twilio or a custom provider, with text or voice delivery.

### Security *(group)*

#### Attack Protection

Bot detection, suspicious-IP throttling, brute-force protection, breached-password detection.

#### Access Control

Rules that block, allow or redirect requests to the tenant, in the maintainer's view similar to a Cloudflare-style edge firewall.

#### Multi-factor Auth

WebAuthn with security keys, WebAuthn with device biometrics, one-time passwords, push notifications through the vendor's authenticator app, phone messages, recovery codes, and Duo Security.

#### Monitoring

Integrations with Datadog, Splunk and Sumo Logic (see https://auth0.com/docs/deploy-monitor/logs).

### Actions *(group)*

#### Triggers

The same trigger points as the Library below. Custom code can be attached to each.

#### Forms

A visual flow builder, like a flowchart. It looks complicated to implement.

#### Library

Custom actions that run at each step. The maintainer considers these **an important feature**: they allow custom changes to flows and have their own environment variables (secrets). Trigger points:
- login / post-login
- machine-to-machine / client credentials
- pre user registration
- post user registration
- post change password
- send phone message
- password reset / post challenge

### Event Streams

Event streams to webhooks, AWS EventBridge or Actions.

### Monitoring *(group)*

#### Logs

A searchable list of log events.

#### Log Streams

Custom log streams.

#### Action Logs

Real-time logs from Actions.

### Marketplace

External plugins.

### Extensions

Extensions added from GitHub repositories.

### Settings

Tenant settings, in tabs: General, Subscription, Tenant Members, Custom Domains, Relying Party IDs, Signing Keys, Encryption Keys, Advanced.
