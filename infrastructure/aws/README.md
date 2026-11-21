# AWS Infrastructure Reference & Terraform Architecture

**Governing Document:** `docs/DCMP_DevOps_and_Deployment_Guide_v1.0.docx`

## Architecture Components

The production deployment runs on AWS using the following managed services:

1. **Compute:** Amazon ECS with AWS Fargate (or Amazon EKS) running containerized NestJS modular monolith tasks behind an Application Load Balancer (ALB).
2. **Database:** Amazon RDS for PostgreSQL 16 (Multi-AZ, read replica, automated backups with PITR).
3. **Cache & Queues:** Amazon ElastiCache for Redis 7 (Cluster mode, BullMQ worker queues).
4. **Object Storage:** Amazon S3 with SSE-KMS encryption for private checklist evidence, photos, signatures, and PDF inspection reports.
5. **CDN & Edge:** Amazon CloudFront with AWS WAF for customer-web, platform-admin, and API rate limiting.
6. **Observability:** AWS CloudWatch, AWS X-Ray / OpenTelemetry, and Sentry for error tracking.

Detailed Terraform / OpenTofu modules will be provisioned in the DevOps deployment sprint.
