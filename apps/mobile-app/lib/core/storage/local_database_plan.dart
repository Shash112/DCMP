/// Local Database Integration Plan for DCMP Mobile App
/// Specification: DCMP_Mobile_Offline_Sync_Specification_v1.0.docx Section 3
///
/// Proposed Driver: Drift (drift + drift_flutter) on top of SQLite
///
/// Schema Architecture:
/// 1. local_checklist_templates: Cached checklist metadata and schema definitions
/// 2. local_checklist_sections: Section groupings and ordering
/// 3. local_checklist_questions: Dynamic questions, types, requirement rules
/// 4. local_question_options: Multiple-choice options, failure flags, scores
/// 5. local_question_conditions: Conditional branching rules (show/hide/require)
/// 6. local_assignments: Scheduled work assigned to this inspector/device
/// 7. local_inspections: Inspection execution drafts, timestamps, overall status
/// 8. local_responses: User answers, notes, fail flags per question
/// 9. local_evidence_queue: Staged photos, signatures, file paths awaiting sync
/// 10. local_sync_log: Idempotent operation log, sync batch IDs, conflict markers
///
/// Implementation Phase: Phase 2 (Offline Engine & Sync Protocol)
class LocalDatabasePlan {
  static const String databaseName = 'dcmp_offline.sqlite';
  static const int schemaVersion = 1;

  static const List<String> plannedTables = [
    'local_checklist_templates',
    'local_checklist_sections',
    'local_checklist_questions',
    'local_question_options',
    'local_question_conditions',
    'local_assignments',
    'local_inspections',
    'local_responses',
    'local_evidence_queue',
    'local_sync_log',
  ];
}
