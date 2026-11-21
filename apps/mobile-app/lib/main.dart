import 'package:flutter/material.dart';
import 'core/theme/app_theme.dart';
import 'core/routing/app_router.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const DcmpMobileApp());
}

class DcmpMobileApp extends StatelessWidget {
  const DcmpMobileApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'DCMP Mobile',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.lightTheme,
      onGenerateRoute: AppRouter.onGenerateRoute,
      initialRoute: AppRouter.routeDashboard,
    );
  }
}
