# ADR 0005: desktop-browser control plane

- Status: Accepted
- Date: 2026-07-15

## Context

The operator needs one research and operations interface without adding native
desktop or mobile packaging and update lifecycles.

## Decision

Build a static React, strict-TypeScript, and Vite SPA for desktop browsers at
1280x720 or larger. Support Chromium, Firefox, and WebKit. Native desktop,
native mobile, PWA, service-worker, and offline-trading behavior are out of
scope.

FastAPI is the only browser backend. REST performs queries and durable commands;
resumable SSE carries compact resource-version events. The client never
optimistically completes trading commands. Paper and live use separate
hostnames with permanent environment identity and no in-app switch.

Auth0 OIDC tokens remain server-side. The browser uses a secure HTTP-only
session cookie plus CSRF protection. Broker/vendor credentials never enter the
browser. Strategy code remains in the repository; the UI selects versions and
edits validated parameters only.

## Consequences

Browser contract drift, stale-state behavior, command confirmation, accessibility,
and desktop cross-engine workflows are CI-tested. Mobile layouts and native
installers require a future ADR.
