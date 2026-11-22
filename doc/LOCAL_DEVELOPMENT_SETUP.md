# DCMP — Local Development Environment Setup Guide

**Product:** Digital Checklist Management Platform (DCMP)  
**Governance:** DevOps Engineer & Technical Lead  
**Phase:** Phase 1.1 Verification Baseline  
**Host Target:** Windows 10/11 & Linux/macOS

---

## 1. Prerequisites & Workstation Audit

Ensure the following runtimes and tools are installed and configured on your workstation:

| Tool               | Required Version               | Status on Windows Host                                   | Purpose                             | Installation / Remediation              |
| ------------------ | ------------------------------ | -------------------------------------------------------- | ----------------------------------- | --------------------------------------- |
| **Node.js**        | `>= 20.0.0` (LTS)              | Installed (`v26.13.0`)                                   | Backend & Next.js runtime           | `winget install OpenJS.NodeJS.LTS`      |
| **pnpm**           | `>= 9.0.0`                     | Installed (`v9.15.9`)                                    | Monorepo workspace package manager  | `npm install -g pnpm@9`                 |
| **Git**            | `>= 2.40.0`                    | Installed (`v2.56.0`)                                    | Source version control              | `winget install Git.Git`                |
| **Flutter SDK**    | `>= 3.38.0` (Dart `>= 3.10.0`) | Installed (`v3.38.6`, Dart `3.10.7` at `C:\flutter\bin`) | Android mobile client development   | Add `C:\flutter\bin` to User `PATH`     |
| **Java JDK 17**    | `17.x` (LTS)                   | Incomplete (directory exists without `bin/java.exe`)     | Android build toolchain & Gradle    | `winget install Microsoft.OpenJDK.17`   |
| **Android SDK**    | API Level 34+                  | Installed at `AppData\Local\Android\Sdk` (`adb v1.0.41`) | Android emulator & app deployment   | Install `cmdline-tools` via SDK Manager |
| **Docker Desktop** | `>= 24.0.0`                    | Not Installed                                            | PostgreSQL 16 & Redis 7 containers  | `winget install Docker.DockerDesktop`   |
| **Docker Compose** | `>= 2.20.0` (v2)               | Not Installed (bundled with Docker Desktop)              | Multi-container local orchestration | Bundled with Docker Desktop             |

---

## 2. Windows Setup Instructions

### 2.1 Java JDK 17 Installation

Android builds and Gradle require a valid Java Development Kit (JDK 17).

1. Install Microsoft OpenJDK 17 using Windows Package Manager (`winget`):

   ```powershell
   winget install Microsoft.OpenJDK.17
   ```

   _Alternative:_ `winget install EclipseAdoptium.Temurin.17.JDK`

2. Verify environment variable configuration:

   ```powershell
   [System.Environment]::SetEnvironmentVariable("JAVA_HOME", "C:\Program Files\Microsoft\jdk-17.0.x", "User")
   $env:JAVA_HOME = "C:\Program Files\Microsoft\jdk-17.0.x"
   ```

3. Confirm verification:
   ```powershell
   java -version
   javac -version
   ```

### 2.2 Flutter SDK Path Configuration

If Flutter is installed at `C:\flutter\bin` but not recognized in new terminal sessions:

1. Add `C:\flutter\bin` to your User `PATH`:

   ```powershell
   [Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\flutter\bin", "User")
   ```

2. Run Flutter Doctor to verify components:
   ```powershell
   flutter doctor
   ```

### 2.3 Android SDK & Virtual Device (AVD) Setup

1. Open Android Studio or use `sdkmanager` to install required components:

   ```powershell
   # Ensure cmdline-tools is installed
   & "$env:ANDROID_HOME\cmdline-tools\latest\bin\sdkmanager.bat" "cmdline-tools;latest" "platform-tools" "platforms;android-34" "build-tools;34.0.0"
   ```

2. Accept Android licenses:

   ```powershell
   flutter doctor --android-licenses
   ```

3. Create and launch an Android Virtual Device (AVD):
   ```powershell
   # List existing emulators
   flutter emulators

   # Create a default emulator if none exists
   flutter emulators --create --name dcmp_pixel_api34

   # Launch emulator
   flutter emulators --launch dcmp_pixel_api34
   ```

### 2.4 Docker Desktop Installation & Configuration

1. Install Docker Desktop for Windows:

   ```powershell
   winget install Docker.DockerDesktop
   ```

2. Restart your computer if prompted to complete WSL 2 (Windows Subsystem for Linux) kernel installation.

3. Launch Docker Desktop and ensure the engine status is **Running**.

4. Verify Docker CLI and Compose in PowerShell:
   ```powershell
   docker --version
   docker compose version
   ```

---

## 3. Quick Start & Monorepo Initialization

### Step 1: Clone Repository & Enter Root

```bash
git clone https://github.com/Shash112/DCMP.git
cd DCMP
```

### Step 2: Configure Environment Variables

Copy `.env.example` to `.env`:

```powershell
# Windows PowerShell
Copy-Item .env.example .env

# Linux / macOS
cp .env.example .env
```

Review the values in `.env`. The defaults are configured for containerized local development.

### Step 3: Install Monorepo Dependencies

```bash
pnpm install --frozen-lockfile
```

### Step 4: Build Shared Workspace Packages

Compile TypeScript packages in dependency order:

```bash
pnpm run build:packages
```

### Step 5: Install Mobile Client Dependencies

```bash
cd apps/mobile-app
flutter pub get
cd ../..
```

---

## 4. Local Infrastructure (Docker Compose)

Once Docker Desktop is running, manage local services using Docker Compose:

### 4.1 Validate Compose File

```bash
docker compose config
```

### 4.2 Start Services

```bash
docker compose up -d
```

### 4.3 Check Service Status

```bash
docker compose ps
```

Expected output:

- `dcmp-postgres` on port `5432` (`healthy`)
- `dcmp-redis` on port `6379` (`healthy`)

### 4.4 Verify Service Readiness

- **PostgreSQL Readiness:**

  ```bash
  docker compose exec postgres pg_isready -U dcmp_user -d dcmp_dev
  ```

- **Redis Readiness:**
  ```bash
  docker compose exec redis redis-cli ping
  # Expected: PONG
  ```

### 4.5 Inspect Service Logs

```bash
docker compose logs --tail=100 -f
```

### 4.6 Verify Volume Persistence

Data persists across container restarts:

```bash
docker compose down
docker compose up -d
```

Docker named volumes `dcmp-postgres-data` and `dcmp-redis-data` preserve all state.

---

## 5. Running Applications Locally

### 5.1 NestJS Backend API

```bash
pnpm dev:backend
```

- **API URL:** `http://localhost:4000/api/v1`
- **Health Check:** `http://localhost:4000/api/v1/health`
- **Swagger Documentation:** `http://localhost:4000/api/docs`

Health check JSON response format:

```json
{
  "success": true,
  "data": {
    "status": "ok",
    "service": "dcmp-backend",
    "version": "0.1.0",
    "environment": "development"
  }
}
```

### 5.2 Customer Web Portal

```bash
pnpm dev:customer-web
```

- **URL:** `http://localhost:3000`
- **Subdomain Routing:** Resolves tenant organization via subdomain or `X-Tenant-Slug` header.

### 5.3 Platform Admin Portal

```bash
pnpm dev:platform-admin
```

- **URL:** `http://localhost:3001`
- **Audience:** Internal SaaS operators and platform administrators.

### 5.4 Mobile Application (Flutter)

Launch with an active Android emulator or physical device connected:

```bash
pnpm dev:mobile
# Or directly:
cd apps/mobile-app
flutter run
```

_Note:_ In the Android emulator, `localhost:4000` is accessed via `http://10.0.2.2:4000/api/v1`.

---

## 6. Verification Quality Gates

Run the complete verification suite before committing code:

```bash
# Code Formatting Check
pnpm run format:check

# ESLint Monorepo Linting
pnpm run lint

# Shared Package Compilation
pnpm run build:packages

# Monorepo TypeScript Type Checking
pnpm run typecheck

# Full Application Build (NestJS + Next.js apps)
pnpm run build:apps

# Flutter Analysis & Tests
cd apps/mobile-app
flutter analyze
flutter test
cd ../..
```
