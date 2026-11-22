# DCMP — Local Development Setup & Validation Guide

**Product:** Digital Checklist Management Platform (DCMP)  
**Governance:** Senior Software Architect, DevOps Engineer & Technical Lead  
**Document Purpose:** Complete Local Environment Validation, Workstation Setup & Handover  
**Date of Validation:** November 22, 2026  
**Validation Status:** **PASSED / READY FOR PHASE 2 DEVELOPMENT**

---

## 1. Workstation Prerequisites

The local development workstation is configured and validated on:

- **Operating System:** Windows 11 (25H2, OS Build 10.0.26200.9711)
- **Virtualization:** Windows Subsystem for Linux (WSL 2) enabled for Docker Desktop
- **Architecture:** x86_64 / amd64

Workstation requirements:

- Elevated terminal rights for Winget/environment path assignments (if modifying system PATH).
- Hardware virtualization enabled in UEFI/BIOS (for Android emulators & WSL 2).
- At least 16 GB RAM (allocated: 8 GB JVM heap configured for Gradle builds via `org.gradle.jvmargs`).

---

## 2. Installed Development Tools & Verified Versions

All tools have been audited, executed, and confirmed operational on the workstation:

| Category                    | Component / Tool      | Verified Version                                     | Path / Executable                                                               | Health / Status                 |
| --------------------------- | --------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------------- | ------------------------------- |
| **JavaScript / TypeScript** | Node.js               | `v26.13.0`                                           | `C:\Program Files\nodejs\node.exe`                                              | **Verified Operational**        |
|                             | pnpm                  | `9.15.9`                                             | `C:\Users\Shashanka.AzureAD\AppData\Roaming\npm\pnpm.ps1`                       | **Verified Operational**        |
|                             | npm                   | `11.20.0`                                            | `C:\Program Files\nodejs\npm.cmd`                                               | **Verified Operational**        |
| **Source Control**          | Git                   | `2.56.0.windows.4`                                   | `C:\Program Files\Git\cmd\git.exe`                                              | **Verified Operational**        |
| **Java Toolchain**          | OpenJDK 17 LTS        | `17.0.21.1` (Microsoft Build)                        | `C:\Program Files\Microsoft\jdk-17.0.21.102-hotspot\bin\java.exe`               | **Verified Operational**        |
|                             | `JAVA_HOME`           | `C:\Program Files\Microsoft\jdk-17.0.21.102-hotspot` | System Environment Variable                                                     | Configured & Active             |
| **Mobile Client**           | Flutter SDK           | `3.50.1` (channel stable)                            | `C:\flutter\bin\flutter.bat` (Git rev: `ae9b586f34`)                            | **Verified Operational**        |
|                             | Dart SDK              | `3.14.0` (stable)                                    | `C:\flutter\bin\cache\dart-sdk\bin\dart.exe`                                    | **Verified Operational**        |
|                             | Flutter JDK Config    | Pointed to OpenJDK 17                                | `flutter config --jdk-dir="C:\Program Files\Microsoft\jdk-17.0.21.102-hotspot"` | Verified in `flutter doctor -v` |
| **Android Toolchain**       | Android SDK           | API Level 36 (`36.1.0`)                              | `C:\Users\Shashanka.AzureAD\AppData\Local\Android\Sdk`                          | **Verified Operational**        |
|                             | Android NDK           | `28.2.13676358`                                      | `C:\Users\Shashanka.AzureAD\AppData\Local\Android\Sdk\ndk\28.2.13676358`        | Verified Installed              |
|                             | Android Debug Bridge  | `1.0.41` (v37.0.0-14910828)                          | `C:\Users\Shashanka.AzureAD\AppData\Local\Android\Sdk\platform-tools\adb.exe`   | **Verified Operational**        |
|                             | Gradle Wrapper        | `9.5.0`                                              | `apps/mobile-app/android/gradle/wrapper/gradle-wrapper.properties`              | **Verified Operational**        |
|                             | Android Gradle Plugin | `9.3.1`                                              | `apps/mobile-app/android/settings.gradle.kts`                                   | **Verified Operational**        |
|                             | Kotlin Support        | Built-in Kotlin (`android.builtInKotlin=true`)       | `apps/mobile-app/android/gradle.properties`                                     | **Verified Operational**        |
| **Containers & DB**         | Docker Desktop        | `4.99.0` (Build 245822)                              | `C:\Program Files\Docker\Docker\Docker Desktop.exe`                             | **Verified Operational**        |
|                             | Docker Engine         | `29.9.3` (API: 1.56)                                 | Running via Docker Desktop WSL 2 backend                                        | **Verified Operational**        |
|                             | Docker Compose        | `v5.7.0`                                             | `docker compose` plugin                                                         | **Verified Operational**        |

_Note on Visual Studio:_ `flutter doctor -v` reports Visual Studio missing for Windows desktop C++ development. This is expected and non-blocking because DCMP target clients are Android mobile and Next.js web.

---

## 3. Docker Infrastructure Setup

The local database and messaging infrastructure is defined in [docker-compose.yml](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/docker-compose.yml):

- **PostgreSQL 16 Alpine (`dcmp-postgres`):**
  - Exposed Host Port: `5432`
  - Internal Database: `dcmp_dev`
  - Default User: `dcmp_user`
  - Named Volume: `dcmp-postgres-data` (persisted on disk)
  - Health check: `pg_isready -U dcmp_user -d dcmp_dev` (Interval: 10s, Retries: 5)
- **Redis 7 Alpine (`dcmp-redis`):**
  - Exposed Host Port: `6379`
  - Named Volume: `dcmp-redis-data` (persisted on disk)
  - Health check: `redis-cli ping` (Interval: 10s, Retries: 5)
- **Network:** `dcmp-network` (bridge driver)

---

## 4. PostgreSQL and Redis Startup Instructions

### Start Containers

```powershell
# From repository root:
pnpm docker:up
# Or directly:
docker compose up -d
```

### Inspect Container Health

```powershell
docker compose ps
```

Both `dcmp-postgres` and `dcmp-redis` must display `healthy`.

### Verify PostgreSQL Connectivity

```powershell
docker compose exec postgres pg_isready -U dcmp_user -d dcmp_dev
# Expected output: /run/postgresql:5432 - accepting connections
```

### Verify Redis Connectivity

```powershell
docker compose exec redis redis-cli ping
# Expected output: PONG
```

### Stop Containers (Preserving Volumes)

```powershell
pnpm docker:down
# Or directly:
docker compose down
```

---

## 5. Backend Startup Instructions

The central NestJS API (`apps/backend`) provides core domain endpoints and OpenAPI Swagger documentation.

### Development Mode (with Hot Reload)

```powershell
pnpm dev:backend
```

### Production Build & Execution

```powershell
# Compile backend
pnpm --filter @dcmp/backend build

# Run compiled build
node apps/backend/dist/main.js
```

### Verified Endpoints

- **Base URL:** `http://localhost:4000/api/v1`
- **Health Check:** `http://localhost:4000/api/v1/health`
  - Expected Response: `200 OK`
  - Payload structure:
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
- **Swagger Documentation:** `http://localhost:4000/api/docs`

---

## 6. Customer Web Startup Instructions

The Next.js 14 tenant portal (`apps/customer-web`):

### Development Mode

```powershell
pnpm dev:customer-web
```

- Listens on `http://localhost:3000`.
- Verified response: HTTP 200 on `/`.

### Production Build & Start

```powershell
pnpm --filter @dcmp/customer-web build
pnpm --filter @dcmp/customer-web start
```

---

## 7. Platform Admin Startup Instructions

The Next.js 14 internal SaaS admin dashboard (`apps/platform-admin`):

### Development Mode

```powershell
pnpm dev:platform-admin
```

- Listens on `http://localhost:3001`.
- Verified response: HTTP 200 on `/`.

### Production Build & Start

```powershell
pnpm --filter @dcmp/platform-admin build
pnpm --filter @dcmp/platform-admin start
```

---

## 8. Flutter Android Setup

The mobile inspection client (`apps/mobile-app`) is built with Flutter 3.50.1 targeting Android API 34+.

### Android Gradle Toolchain

- **Gradle Version:** `9.5.0` (`gradle/wrapper/gradle-wrapper.properties`)
- **Android Gradle Plugin (AGP):** `9.3.1` (`android/settings.gradle.kts`)
- **Built-in Kotlin:** Enabled via `android.builtInKotlin=true` in `gradle.properties`.
- **New DSL:** Enabled via `android.newDsl=true` in `gradle.properties`.
- **Target Compatibility:** Java 17 / JVM 17.
- **Application ID:** `com.dcmp.mobile_app`.

### Verification Commands

```powershell
cd apps/mobile-app

# Dependency resolution
flutter pub get

# Static code analysis
flutter analyze

# Unit & widget smoke tests
flutter test

# Compile Debug APK
flutter build apk --debug
```

---

## 9. Android Emulator Instructions

### Check Connected Devices & Emulators

```powershell
flutter devices
flutter emulators
```

### Verified Active Emulators on Workstation

1. **`emulator-5556`:** `sdk gphone64 x86 64` (Android 17, API 37)
2. **`emulator-5554`:** `Pixel Tablet` (Android 16, API 36)

### Launching an Emulator

```powershell
flutter emulators --launch Pixel_8
# or
flutter emulators --launch Medium_Tablet
```

### Installing and Running on an Emulator

```powershell
# Run directly with Flutter tooling:
cd apps/mobile-app
flutter run -d emulator-5556

# Or install compiled APK via ADB:
adb -s emulator-5556 install -r build\app\outputs\flutter-apk\app-debug.apk
adb -s emulator-5556 shell am start -n com.dcmp.mobile_app/com.dcmp.mobile_app.MainActivity
```

---

## 10. Environment Configuration & Security

1. **Template Integrity:** [.env.example](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/.env.example) maintains full parity with [docker-compose.yml](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/docker-compose.yml).
2. **No Secret Leakage:** Database credentials (`dcmp_dev_password`), JWT secret templates (`min_32_chars`), and AWS mock keys are placeholders.
3. **No Overwrite Policy:** No `.env` file exists or was created during validation.
4. **CORS Isolation:** CORS is restricted to web frontends (`http://localhost:3000,http://localhost:3001`).
5. **Emulator Networking:** Mobile application connects to local backend via `http://10.0.2.2:4000/api/v1` in emulator environments.

---

## 11. Common Troubleshooting Runbook

### Issue: PowerShell Script Execution Blocked

- **Symptom:** `pnpm : File cannot be loaded because running scripts is disabled on this system.`
- **Fix:**
  ```powershell
  Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
  ```

### Issue: Port Conflicts on 3000, 3001, 4000, 5432, 6379

- **Diagnose:**
  ```powershell
  Get-NetTCPConnection -LocalPort 3000, 3001, 4000, 5432, 6379 -ErrorAction SilentlyContinue | Select-Object LocalPort, State, OwningProcess
  ```
- **Fix:** Terminate lingering node/next processes by Process ID:
  ```powershell
  Stop-Process -Id <PID> -Force
  ```

### Issue: Gradle Wrapper Download Socket Timeout on Windows

- **Symptom:** Gradle wrapper fails to download distributions over Java TLS connections.
- **Fix:** Download the distribution manually (e.g. `gradle-9.5.0-all.zip`) and place it directly into the local Gradle wrapper cache:
  `$env:USERPROFILE\.gradle\wrapper\dists\gradle-9.5.0-all\<hash>\`

### Issue: Flutter Defaults to Wrong JDK (e.g. Android Studio JBR 25)

- **Symptom:** Unsupported class file version or Gradle incompatibilities.
- **Fix:** Pin Flutter's JDK to OpenJDK 17:
  ```powershell
  flutter config --jdk-dir="C:\Program Files\Microsoft\jdk-17.0.21.102-hotspot"
  ```

---

## 12. Verified Successful Build Commands

The following command matrix was executed and verified clean during Phase 1.1 validation:

```powershell
# 1. Monorepo dependency sync
pnpm install --frozen-lockfile

# 2. Shared packages build
pnpm run build:packages

# 3. Formatting check
pnpm run format:check

# 4. ESLint monorepo checks
pnpm run lint

# 5. TypeScript monorepo typecheck
pnpm run typecheck

# 6. NestJS Backend compile
pnpm --filter @dcmp/backend build

# 7. Customer Web Next.js compile
pnpm --filter @dcmp/customer-web build

# 8. Platform Admin Next.js compile
pnpm --filter @dcmp/platform-admin build

# 9. Flutter analyze
cd apps/mobile-app && flutter analyze

# 10. Flutter test
flutter test

# 11. Flutter Android debug APK build
flutter build apk --debug
```

---

## 13. Remaining Warnings & Known Limitations

| Item          | Component                     | Type               | Severity     | Description & Recommendation                                                                                                                                                                          |
| ------------- | ----------------------------- | ------------------ | ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **WARN-001**  | `docker-compose.yml`          | Obsolete Attribute | Resolved     | Top-level `version: '3.8'` attribute removed to comply with modern Docker Compose v5+ specification.                                                                                                  |
| **WARN-002**  | `apps/mobile-app`             | Deprecation Notice | Non-blocking | 7 informational hints in `flutter analyze` regarding `package:flutter/material.dart` deprecation in future Flutter releases in favor of `package:material_ui/material_ui.dart`. No functional impact. |
| **WARN-003**  | Workstation Desktop Toolchain | Missing Tool       | Non-blocking | Visual Studio 2022 C++ workload is not installed; not required for DCMP since targets are Android and Web.                                                                                            |
| **MAINT-001** | Docker Desktop                | Available Upgrade  | Non-blocking | Docker Desktop `4.99.0` is installed. Current stable release is `4.100.0` (with Compose v5.7.1). Upgrade is optional via Docker Desktop UI.                                                           |

---

## 14. Development Handover: Flutter Gradle Migration & APK Validation

### Summary of Completed Engineering

During Phase 1 stabilization, Android build compatibility was modernized to align with Flutter 3.50.1 standards:

1. **Java 17 Standardization:** Installed Microsoft OpenJDK 17 LTS (`17.0.21.1`) and configured Flutter via `flutter config --jdk-dir` to prevent runtime conflicts with Android Studio's experimental bundled JRE.
2. **AGP & Gradle Upgrade:**
   - Upgraded Android Gradle Plugin to `9.3.1` in [settings.gradle.kts](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/apps/mobile-app/android/settings.gradle.kts).
   - Upgraded Gradle wrapper to `9.5.0` in [gradle-wrapper.properties](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/apps/mobile-app/android/gradle/wrapper/gradle-wrapper.properties).
3. **Migration to Modern Kotlin DSL:**
   - Configured `android.builtInKotlin=true` and `android.newDsl=true` in `gradle.properties`.
   - Replaced legacy `kotlinOptions { jvmTarget = ... }` with `kotlin { compilerOptions { jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17 } }` in [build.gradle.kts](file:///c:/Users/Shashanka.AzureAD/Desktop/Projects/WLS/DCMP/apps/mobile-app/android/app/build.gradle.kts).
4. **Verified Runtime Deliverable:**
   - Debug APK compiled at: `apps/mobile-app/build/app/outputs/flutter-apk/app-debug.apk`.
   - Successfully installed and executed on:
     - `sdk gphone64 x86 64` (`emulator-5556`)
     - `Pixel Tablet` (`emulator-5554`)
   - Both emulators launched `MainActivity` with live Dart VM services.

### Proposed Documentation Updates

- Update `README.md` and `doc/PROJECT_DOCUMENTATION_INDEX.md` to reference this validation document (`doc/LOCAL_DEVELOPMENT_SETUP_AND_VALIDATION.md`).
- Ensure all incoming Phase 2 engineers use `flutter config --jdk-dir` pointed to Java 17 to prevent Gradle daemon mismatches.
