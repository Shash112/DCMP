import 'package:flutter/material.dart';
import '../../features/activation/activation_screen.dart';
import '../../features/auth/login_screen.dart';
import '../../features/dashboard/dashboard_screen.dart';

class AppRouter {
  static const String routeDashboard = '/';
  static const String routeActivation = '/activation';
  static const String routeLogin = '/login';

  static Route<dynamic> onGenerateRoute(RouteSettings settings) {
    switch (settings.name) {
      case routeDashboard:
        return MaterialPageRoute(builder: (_) => const DashboardScreen());
      case routeActivation:
        return MaterialPageRoute(builder: (_) => const ActivationScreen());
      case routeLogin:
        return MaterialPageRoute(builder: (_) => const LoginScreen());
      default:
        return MaterialPageRoute(builder: (_) => const DashboardScreen());
    }
  }
}
