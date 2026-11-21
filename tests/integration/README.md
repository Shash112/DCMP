# DCMP Integration Tests

**Governing Document:** `docs/DCMP_Detailed_Test_Plan_and_Test_Cases_v1.0.docx` Section 13.2

## Test Scope

Integration tests validate cross-module and infrastructure boundaries:

1. **Tenant Isolation:** Cross-tenant leakage prevention across Organization A and Organization B.
2. **Authentication Flow:** Login, JWT generation, session creation, rotating refresh tokens, logout.
3. **Checklist Immutability:** Publishing checklist versions, version increments, snapshot locking.
4. **Inspection Submission:** Responses validation, evidence linking, score calculation.
5. **Support Access:** Approval-bound temporary access grants.
