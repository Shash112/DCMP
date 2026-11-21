import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Response } from 'express';
import { ERROR_CODES, HTTP_HEADERS } from '@dcmp/api-contracts';
import { ApiErrorResponse, ApiErrorDetail } from '@dcmp/shared-types';
import { ExtendedRequest } from '../middleware/request-id.middleware';

@Catch()
export class GlobalHttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(GlobalHttpExceptionFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<ExtendedRequest>();

    const requestId =
      request.requestId || (request.headers[HTTP_HEADERS.REQUEST_ID] as string) || '';

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let code: string = ERROR_CODES.INTERNAL_SERVER_ERROR;
    let message = 'An unexpected internal error occurred.';
    let details: ApiErrorDetail[] | undefined = undefined;

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const res = exception.getResponse();

      if (typeof res === 'string') {
        message = res;
      } else if (typeof res === 'object' && res !== null) {
        const body = res as Record<string, unknown>;
        message = (body.message as string) || message;
        code = (body.code as string) || this.mapStatusToErrorCode(status);

        if (Array.isArray(body.message)) {
          code = ERROR_CODES.VALIDATION_ERROR;
          message = 'Validation failed for one or more fields.';
          details = body.message.map((msg: string) => ({
            issue: msg,
          }));
        } else if (Array.isArray(body.errors)) {
          details = body.errors as ApiErrorDetail[];
        }
      }
    } else if (exception instanceof Error) {
      message = exception.message;
      this.logger.error(`Unhandled error: ${exception.message}`, exception.stack);
    }

    const errorResponse: ApiErrorResponse = {
      success: false,
      error: {
        code,
        message,
        details,
        requestId,
      },
    };

    response.status(status).json(errorResponse);
  }

  private mapStatusToErrorCode(status: number): string {
    switch (status) {
      case HttpStatus.BAD_REQUEST:
        return ERROR_CODES.BAD_REQUEST;
      case HttpStatus.UNAUTHORIZED:
        return ERROR_CODES.UNAUTHENTICATED;
      case HttpStatus.FORBIDDEN:
        return ERROR_CODES.FORBIDDEN;
      case HttpStatus.NOT_FOUND:
        return ERROR_CODES.RESOURCE_NOT_FOUND;
      case HttpStatus.CONFLICT:
        return ERROR_CODES.STATE_CONFLICT;
      case HttpStatus.UNPROCESSABLE_ENTITY:
        return ERROR_CODES.VALIDATION_ERROR;
      default:
        return ERROR_CODES.INTERNAL_SERVER_ERROR;
    }
  }
}
