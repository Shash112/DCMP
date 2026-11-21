import 'package:flutter/material.dart';
import '../../core/constants/app_colors.dart';

class ActivationScreen extends StatelessWidget {
  const ActivationScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Device Activation'),
      ),
      body: Padding(
        padding: const EdgeInsets.all(24.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(
              Icons.phonelink_setup,
              size: 64,
              color: AppColors.primary,
            ),
            const SizedBox(height: 24),
            const Text(
              'Activate Device',
              style: TextStyle(
                fontSize: 22,
                fontWeight: FontWeight.bold,
                color: AppColors.textPrimary,
              ),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 8),
            const Text(
              'Enter your organization activation code to configure this device.',
              style: TextStyle(fontSize: 14, color: AppColors.textSecondary),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 32),
            TextField(
              decoration: const InputDecoration(
                labelText: 'Activation Code',
                hintText: 'e.g. DCMP-ACT-XXXX-XXXX',
                prefixIcon: Icon(Icons.vpn_key),
              ),
            ),
            const SizedBox(height: 24),
            ElevatedButton(
              onPressed: () {},
              child: const Text('Validate & Activate'),
            ),
          ],
        ),
      ),
    );
  }
}
