# DCMP — Local Development Environment Setup Guide

**Product:** Digital Checklist Management Platform (DCMP)  
**Governance:** DevOps Engineer & Technical Lead  
**Phase:** Phase 1 Baseline

---

## 1. Prerequisites

Ensure the following runtimes and tools are installed on your workstation:

| Tool                        | Minimum Version                           | Purpose                             |
| --------------------------- | ----------------------------------------- | ----------------------------------- |
| **Node.js**                 | `>= 20.0.0` (Recommended: v20 LTS or v22) | Backend & Web runtime               |
| **pnpm**                    | `>= 9.0.0`                                | Monorepo workspace package manager  |
| **Git**                     | `>= 2.40.0`                               | Version control                     |
| **Docker & Docker Compose** | `>= 24.0.0` (Docker Compose v2)           | Local PostgreSQL and Redis services |
| **Flutter SDK**             | `>= 3.38.0` (Dart `>= 3.10.0`)            | Android Mobile client development   |

---

## 2. Quick Start

### Step 1: Clone Repository & Enter Root

```bash
git clone <repo-url> DCMP
cd DCMP
```

### Step 2: Environment Configuration

Copy the provided `.env.example` template to `.env`:

```bash
# On Linux / macOS:
cp .env.example .env

# On Windows PowerShell:
Copy-Item .env.example .env
```

Review the values in `.env`. The defaults are pre-configured for local containerized development.

### Step 3: Install Monorepo Dependencies

```bash
# Install pnpm if not already in PATH:
npm install -g pnpm@9

# Install all TypeScript packages and applications:
pnpm install
```

### Step 4: Install Flutter Dependencies

```bash
cd apps/mobile-app
flutter pub get
cd ../..
```

### Step 5: Start Local Infrastructure

Start the PostgreSQL 16 database and Redis 7 service:

```bash
pnpm docker:up
# Or directly:
docker compose up -d
```

Verify service health:

```bash
docker compose ps
```

Both `dcmp-postgres` and `dcmp-redis` should report `healthy`.

---

## 3. Running Applications Locally

Each application can be run independently or concurrently:

### 3.1 Start NestJS Backend API

```bash
pnpm dev:backend
```

- **API URL:** `http://localhost:4000/api/v1`
- **Health Check:** `http://localhost:4000/api/v1/health`
- **Swagger Documentation:** `http://localhost:4000/api/docs`

### 3.2 Start Customer Web Portal

```bash
pnpm dev:customer-web
```

- **Web URL:** `http://localhost:3000`
- **Port:** `3000`

### 3.3 Start Platform Admin Dashboard

```bash
pnpm dev:platform-admin
```

- **Web URL:** `http://localhost:3001`
- **Port:** `3001`

### 3.4 Start Flutter Mobile Application

Ensure an Android Emulator is running or an Android device is connected via USB:

```bash
pnpm dev:mobile
# Or directly:
cd apps/mobile-app
flutter run
```

---

## 4. Verification & Quality Gates

Run the following commands to ensure all checks pass before pushing code:

### 4.1 Formatting & Linting

```bash
# Check code formatting:
pnpm run format:check

# Format files with Prettier:
pnpm run format

# Run ESLint across monorepo:
pnpm run lint
```

### 4.2 Type Checking

```bash
pnpm run typecheck
```

### 4.3 Build All Packages & Web Applications

```bash
pnpm run build
```

### 4.4 Flutter Analysis & Tests

```bash
cd apps/mobile-app
flutter analyze
flutter test
cd ../..
```

---

## 5. Troubleshooting & FAQ

### Issue: `pnpm : File cannot be loaded because running scripts is disabled` (Windows)

**Solution:** PowerShell execution policy restricts script execution. Run:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

### Issue: Docker daemon is not running / `docker : The term 'docker' is not recognized`

**Solution:** Ensure Docker Desktop is installed and running. If Docker Desktop cannot be installed on your workstation, configure `DATABASE_URL` and `REDIS_HOST` in `.env` to point to an external or cloud PostgreSQL/Redis instance.

### Issue: Android Emulator cannot reach `localhost:4000`

**Solution:** Android emulators map the host workstation's `localhost` to `10.0.2.2`. The default mobile environment configuration in `apps/mobile-app/lib/core/constants/api_constants.dart` already defaults to `http://10.0.2.2:4000/api/v1`. If using a physical device connected via Wi-Fi, pass `--dart-define=DCMP_API_BASE_URL=http://<YOUR_LAN_IP>:4000/api/v1`.
