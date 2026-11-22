import { Controller, Get, Inject, ServiceUnavailableException } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { HealthService, HealthCheckResult, ReadinessResult } from './health.service';

@ApiTags('Health')
@Controller('health')
export class HealthController {
  constructor(@Inject(HealthService) private readonly healthService: HealthService) {}

  @Get()
  @ApiOperation({ summary: 'Backend service health check (liveness-compatible)' })
  @ApiResponse({ status: 200, description: 'Service is operational' })
  check(): HealthCheckResult {
    return this.healthService.check();
  }

  @Get('live')
  @ApiOperation({ summary: 'Liveness probe — process up only' })
  live(): HealthCheckResult {
    return this.healthService.liveness();
  }

  @Get('ready')
  @ApiOperation({ summary: 'Readiness probe — PostgreSQL + Redis when required' })
  async ready(): Promise<ReadinessResult> {
    const result = await this.healthService.readiness();
    if (!result.ready) {
      throw new ServiceUnavailableException(result);
    }
    return result;
  }
}
