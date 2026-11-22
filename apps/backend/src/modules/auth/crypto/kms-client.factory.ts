import { KMSClient } from '@aws-sdk/client-kms';
import type { DcmpKmsConfig } from './kms-config';

/**
 * Prefer IAM workload identity / shared credential chain.
 * Never hardcode access keys. Optional endpoint for isolated LocalStack labs only.
 */
export function createKmsClient(cfg: DcmpKmsConfig): KMSClient {
  return new KMSClient({
    region: cfg.region,
    ...(cfg.endpoint ? { endpoint: cfg.endpoint } : {}),
  });
}
