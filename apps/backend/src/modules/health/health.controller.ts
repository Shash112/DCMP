import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { HealthService, HealthCheckResult } from './health.service';

@ApiTags('Health')
@Controller('health')
export class HealthController {
  constructor(private readonly healthService: HealthService) {}

  @Get()
  @ApiOperation({ summary: 'Backend service health check' })
  @ApiResponse({
    status: 200,
    description: 'Service is operational',
    schema: {
      example: {
        success: true,
        data: {
          status: 'ok',
          service: 'dcmp-backend',
          version: '0.1.0',
          timestamp: '2026-11-22T01:00:00.000Z',
          environment: 'development',
          uptimeSeconds: 120,
        },
        meta: {
          requestId: 'b4a1b0cd-7cb2-4a0b-a1bb-20e3ad54a2b1',
          timestamp: '2026-11-22T01:00:00.000Z',
        },
      },
    },
  })
  check(): HealthCheckResult {
    return this.healthService.check();
  }
}
