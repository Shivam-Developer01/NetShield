# NetShield — Backend Microservice (`backend/`)

## Overview
Node.js + Express + MongoDB microservice acting as the application layer for the NetShield platform. Handles user authentication, JWT session security, Double-Submit Cookie CSRF protection, rate limiting, Helmet security headers, security audit logging, role-based authorization (ADMIN, ANALYST, VIEWER), persistent threat logging, alert generation, telemetry calculation, correlation ID tracing (`X-Request-ID`), structured logging, and HTTP IPC with the Python FastAPI ML container.

---

## Production Deployment & Features
- **Dockerized**: Containerized via `./backend/Dockerfile` (`node:20-slim`).
- **Startup Validation**: Startup environment validation prevents launching in production with default secrets.
- **Request Correlation**: Propagates `X-Request-ID` correlation ID across Express middleware -> logger -> Axios IPC -> FastAPI ML Service.
- **Structured Logging**: Outputs JSON structured logs with automatic redaction of passwords, hashes, JWTs, and CSRF secrets.
- **Graceful Shutdown**: Listens for `SIGINT`/`SIGTERM` to close HTTP listener, disconnect Mongoose DB connection, and exit cleanly.
- **Container Health Check**: GET `/health` returns status of Node backend, MongoDB connection, and FastAPI ML service.

---

## Authentication & Security Systems
- **Password Hashing**: `bcryptjs` (10 salt rounds).
- **Token Format**: JWT signed with `JWT_SECRET`.
- **Cookie Security**: HTTP-only cookie (`netshield_token`) + readable Double-Submit Cookie (`XSRF-TOKEN`).
- **CSRF Protection**: State-changing requests (`POST`, `PATCH`, `DELETE`) require matching `X-XSRF-TOKEN` header and `XSRF-TOKEN` cookie (`csrfProtection.js`).
- **Rate Limiting**: `POST /api/auth/login` and `POST /api/auth/register` rate limited via `express-rate-limit` (`rateLimiter.js`).
- **Security Audit Logging**: Logged via `auditLogger.js` for `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `LOGOUT`, `REGISTER`, `USER_ACTIVATED`, `USER_DEACTIVATED`, `ROLE_CHANGED`, `USER_DELETED`. Credential redacting enforced.
- **Roles**:
  - `ADMIN`: Full access (Predictions, Alerts, Settings, User Management).
  - `ANALYST`: Operations access (Predictions, Alerts, View Settings; No User Management).
  - `VIEWER`: Read-only access (View Dashboard, Predictions, Alerts, Metrics; No actions/modifications).

---

## Admin Seeding Script
To seed the default admin account:
```bash
cmd /c "npm run seed:admin"
```

---

## Running Tests
```bash
cmd /c "npm test"
```
Ran Jest test suite: **8/8 Test Suites Passed, 38/38 Tests Passed (100%)**.
