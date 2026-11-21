import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { Logger } from 'nestjs-pino';
import { AppModule } from './app.module';
import { GlobalHttpExceptionFilter } from './common/filters/http-exception.filter';
import { ResponseTransformInterceptor } from './common/interceptors/response.interceptor';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { bufferLogs: true });

  const configService = app.get(ConfigService);
  const port = configService.get<number>('port', 4000);
  const apiPrefix = configService.get<string>('apiPrefix', '/api/v1');
  const corsOrigins = configService.get<string[]>('corsOrigin', [
    'http://localhost:3000',
    'http://localhost:3001',
  ]);

  // Use structured Pino logger
  app.useLogger(app.get(Logger));

  // Enable CORS
  app.enableCors({
    origin: corsOrigins,
    credentials: true,
  });

  // Global API Prefix (/api/v1)
  app.setGlobalPrefix(apiPrefix.replace(/^\//, ''));

  // Global Validation Pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: false,
    }),
  );

  // Global Response Interceptor
  app.useGlobalInterceptors(new ResponseTransformInterceptor());

  // Global Exception Filter
  app.useGlobalFilters(new GlobalHttpExceptionFilter());

  // OpenAPI / Swagger Documentation
  const swaggerConfig = new DocumentBuilder()
    .setTitle('DCMP Central API')
    .setDescription(
      'Digital Checklist Management Platform (DCMP) REST API - Multi-Tenant SaaS Backend',
    )
    .setVersion('1.0.0')
    .addBearerAuth()
    .addTag('Health', 'System health and diagnostics')
    .addTag('Auth', 'Authentication and session management')
    .addTag('Organizations', 'Tenant and organization profile')
    .addTag('Checklists', 'Checklist templates and versions')
    .addTag('Inspections', 'Inspection execution and submission')
    .addTag('Licensing', 'License and device activation')
    .build();

  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('api/docs', app, document);

  await app.listen(port);
  const appUrl = await app.getUrl();
  const logger = app.get(Logger);
  logger.log(`DCMP Backend is running on: ${appUrl}/${apiPrefix.replace(/^\//, '')}`);
  logger.log(`Swagger OpenAPI Documentation: ${appUrl}/api/docs`);
}

bootstrap();
