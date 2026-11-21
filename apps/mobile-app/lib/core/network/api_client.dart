import 'dart:convert';
import 'package:http/http.dart' as http;
import '../constants/api_constants.dart';

/// Foundation API Client for DCMP Mobile App
/// Handles standard request headers, correlation IDs, and token injection
class MobileApiClient {
  final String baseUrl;
  String? _accessToken;
  String? _deviceId;
  String? _tenantSlug;

  MobileApiClient({String? customBaseUrl})
      : baseUrl = customBaseUrl ?? ApiConstants.defaultBaseUrl;

  void setAuthCredentials({
    required String accessToken,
    required String deviceId,
    required String tenantSlug,
  }) {
    _accessToken = accessToken;
    _deviceId = deviceId;
    _tenantSlug = tenantSlug;
  }

  void clearAuthCredentials() {
    _accessToken = null;
    _deviceId = null;
    _tenantSlug = null;
  }

  Map<String, String> _buildHeaders() {
    final headers = <String, String>{
      'Content-Type': 'application/json',
      ApiConstants.headerClientVersion: '1.0.0',
    };

    if (_accessToken != null) {
      headers[ApiConstants.headerAuthorization] = 'Bearer $_accessToken';
    }
    if (_deviceId != null) {
      headers[ApiConstants.headerDeviceId] = _deviceId!;
    }
    if (_tenantSlug != null) {
      headers[ApiConstants.headerTenantSlug] = _tenantSlug!;
    }

    return headers;
  }

  Future<Map<String, dynamic>> get(String endpoint) async {
    final uri = Uri.parse('$baseUrl$endpoint');
    final response = await http.get(uri, headers: _buildHeaders());
    return jsonDecode(response.body) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> post(
    String endpoint,
    Map<String, dynamic> body,
  ) async {
    final uri = Uri.parse('$baseUrl$endpoint');
    final response = await http.post(
      uri,
      headers: _buildHeaders(),
      body: jsonEncode(body),
    );
    return jsonDecode(response.body) as Map<String, dynamic>;
  }
}
