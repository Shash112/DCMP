/// DCMP Mobile API Constants and Environment Configuration
/// Supports `--dart-define=DCMP_API_BASE_URL=...` at build time
class ApiConstants {
  static const String defaultBaseUrl = String.fromEnvironment(
    'DCMP_API_BASE_URL',
    defaultValue: 'http://10.0.2.2:4000/api/v1', // Standard Android Emulator host mapping
  );

  static const String headerRequestId = 'x-request-id';
  static const String headerTenantSlug = 'x-tenant-slug';
  static const String headerDeviceId = 'x-device-id';
  static const String headerClientVersion = 'x-client-version';
  static const String headerAuthorization = 'authorization';

  static const String pathHealth = '/health';
  static const String pathActivate = '/licenses/activate';
  static const String pathLogin = '/auth/login';
  static const String pathRefresh = '/auth/refresh';
  static const String pathSyncPull = '/sync/pull';
  static const String pathSyncPush = '/sync/push';
}
