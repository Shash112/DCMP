/// Secure Storage Integration Plan for DCMP Mobile App
/// Specification: DCMP_Security_and_Tenant_Isolation_Design_v1.0.docx Section 4.3
/// Driver: flutter_secure_storage (backed by Android Keystore / EncryptedSharedPreferences)
///
/// Keys to be stored securely:
/// - KEY_DEVICE_TOKEN: Hardware-bound activation token issued by Central Backend
/// - KEY_INSTALLATION_ID: Unique UUID generated on first launch
/// - KEY_ACCESS_TOKEN: Short-lived JWT (15-minute validity)
/// - KEY_REFRESH_TOKEN: Hashed rotating refresh token
/// - KEY_TENANT_SLUG: Active customer organization slug
/// - KEY_LICENSE_CACHE: Encrypted snapshot of active entitlements
///
/// Security Guardrail:
/// - Plaintext secrets, passwords, and tokens MUST NEVER be stored in plain SQLite or shared preferences.
class SecureStoragePlan {
  static const String keyDeviceToken = 'dcmp_sec_device_token';
  static const String keyInstallationId = 'dcmp_sec_installation_id';
  static const String keyAccessToken = 'dcmp_sec_access_token';
  static const String keyRefreshToken = 'dcmp_sec_refresh_token';
  static const String keyTenantSlug = 'dcmp_sec_tenant_slug';
  static const String keyLicenseCache = 'dcmp_sec_license_cache';
}
