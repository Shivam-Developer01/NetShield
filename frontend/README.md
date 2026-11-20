# NetShield — React SOC Dashboard (`frontend/`)

## Overview
A modern, dark-themed Cybersecurity Operations Center (SOC) dashboard built with React 18, Vite, Recharts, and Lucide React. Features user authentication, role-based UI controls, CSRF token handling, paginated threat logs, alert management, manual intrusion testing, and system telemetry metrics.

---

## Production Build & Docker Deployment
- **Multi-Stage Dockerfile**: Multi-stage build (`node:20-alpine` build -> `nginx:alpine` production web container listening on port `5173`).
- **Nginx Reverse Proxy**: Configured via `frontend/nginx.conf` to serve Vite SPA static assets and proxy `/api` requests to Node.js backend container (`http://backend:5000/api`).
- **Build Command**:
  ```bash
  cmd /c "npm run build"
  ```
  Verified: React production bundle generated in `/app/dist`.

---

## Authentication & Security Integration
- **Authentication State**: `AuthContext` provider handling session restoration via `GET /api/auth/me`.
- **Token Security**: Tokens are sent exclusively via HTTP-only cookies (`netshield_token`). `localStorage` token storage is eliminated.
- **CSRF Token Handling**: Axios client (`api.js`) automatically reads non-HttpOnly `XSRF-TOKEN` cookie and attaches `X-XSRF-TOKEN` header on non-GET state-changing requests (`POST`, `PATCH`, `DELETE`).
- **Protected Routes**: `<ProtectedRoute allowedRoles={['ADMIN', 'ANALYST']}>` redirects unauthenticated users to `/login`.
- **Role Awareness**:
  - `ADMIN`: Access to all views + User Management page (`/users`).
  - `ANALYST`: Access to Dashboard, Predictions, Alerts, Predict form, Metrics, Settings (Read-Only).
  - `VIEWER`: Read-only view of Dashboard, Predictions, Alerts, Metrics; prediction submission and alert status controls hidden/disabled.

---

## Running Tests
```bash
cmd /c "npm test"
```
Ran Vitest test suite: **2/2 Test Suites Passed, 9/9 Tests Passed (100%)**.
