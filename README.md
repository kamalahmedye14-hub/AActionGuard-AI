# ActionGuard AI

**AI Agent Security & Data Loss Prevention Platform**

ActionGuard AI is a prototype security platform designed to help organizations protect AI agents and prevent sensitive data exposure.

## 1. Project Overview

The platform aims to detect sensitive information, evaluate potentially risky actions, and maintain security audit records.

## 2. Core Features

- **Sensitive Data Detection:** Detects API keys, credentials, email addresses, and possible phone numbers.
- **Data Protection:** Blocks credential exposure and redacts detected personal information.
- **Action Authorization:** Evaluates actions and resources against security rules.
- **Security Decisions:** Supports ALLOW, BLOCK, REDACT, and REVIEW decisions.
- **Audit Records:** Records security scan and authorization events.
- **Multilingual Interface:** Supports English, Arabic, and Chinese.

## 3. Technology

- TypeScript
- React
- Vite
- Node.js
- SQLite

## 4. Project Structure

- `App.tsx` — Main application interface.
- `i18n.ts` — Language translations.
- `server/` — Backend services and security logic.
- `security.ts` — Sensitive data detection and security decisions.
- `db.ts` — Database configuration.
- `security.test.ts` — Security tests.

## 5. Security Workflow

1. Receive text or an action request.
2. Scan for sensitive information.
3. Evaluate the security policy.
4. Return an appropriate security decision.
5. Record the event for auditing.

## 6. Current Project Status

ActionGuard AI is currently an MVP prototype. It requires additional testing, authentication, tenant isolation, and security hardening before production deployment.

## 7. Disclaimer

This prototype is intended for development and evaluation. It does not yet guarantee protection of all third-party AI traffic.

## 8. License

License and distribution terms have not yet been defined.
