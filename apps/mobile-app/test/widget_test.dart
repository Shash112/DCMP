import 'package:flutter_test/flutter_test.dart';
import 'package:mobile_app/main.dart';

void main() {
  testWidgets('DCMP mobile app smoke test', (WidgetTester tester) async {
    await tester.pumpWidget(const DcmpMobileApp());
    expect(find.text('DCMP Inspector'), findsOneWidget);
    expect(find.text('Assigned Inspections'), findsOneWidget);
  });
}
