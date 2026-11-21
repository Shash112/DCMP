import { Injectable } from '@nestjs/common';

export interface HealthCheckResult {
  status: 'ok' | 'degraded' | 'down';
  service: string;
  version: string;
  timestamp: string;
  environment: string;
  uptimeSeconds: number;
}

@Injectable()
export class HealthService {
  private readonly startTime = Date.now();

  check(): HealthCheckResult {
    return {
      status: 'ok',
      service: 'dcmp-backend',
      version: '0.1.0',
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      uptimeSeconds: Math.floor((Date.now() - this.startTime) / 1000),
    };
  }
}
