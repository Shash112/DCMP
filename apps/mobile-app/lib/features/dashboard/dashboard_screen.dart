import 'package:flutter/material.dart';
import '../../core/constants/app_colors.dart';

class DashboardScreen extends StatelessWidget {
  const DashboardScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('DCMP Inspector'),
        actions: [
          IconButton(
            icon: const Icon(Icons.sync),
            tooltip: 'Sync Offline Queue',
            onPressed: () {
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Offline sync engine scheduled for Phase 2.')),
              );
            },
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        const Text(
                          'Device Status',
                          style: TextStyle(
                            fontSize: 16,
                            fontWeight: FontWeight.bold,
                            color: AppColors.textPrimary,
                          ),
                        ),
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                          decoration: BoxDecoration(
                            color: AppColors.primaryLight,
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: const Text(
                            'Phase 1 Baseline',
                            style: TextStyle(
                              fontSize: 12,
                              color: AppColors.primary,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    const Text(
                      'Common Android APK foundation initialized. Offline SQLite schema, secure storage plans, and API client foundation configured.',
                      style: TextStyle(fontSize: 13, color: AppColors.textSecondary, height: 1.4),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),
            const Text(
              'Assigned Inspections',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.bold,
                color: AppColors.textPrimary,
              ),
            ),
            const SizedBox(height: 12),
            Card(
              child: ListTile(
                leading: const CircleAvatar(
                  backgroundColor: AppColors.primaryLight,
                  child: Icon(Icons.checklist, color: AppColors.primary),
                ),
                title: const Text('Facility Safety Audit'),
                subtitle: const Text('Due Today • Offline Capable'),
                trailing: const Icon(Icons.chevron_right),
                onTap: () {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Checklist execution module scheduled for Phase 2.')),
                  );
                },
              ),
            ),
          ],
        ),
      ),
    );
  }
}
