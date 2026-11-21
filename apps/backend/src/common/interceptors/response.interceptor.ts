import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { ApiSuccessResponse } from '@dcmp/shared-types';
import { ExtendedRequest } from '../middleware/request-id.middleware';
import { HTTP_HEADERS } from '@dcmp/api-contracts';

@Injectable()
export class ResponseTransformInterceptor<T> implements NestInterceptor<T, ApiSuccessResponse<T>> {
  intercept(context: ExecutionContext, next: CallHandler): Observable<ApiSuccessResponse<T>> {
    const request = context.switchToHttp().getRequest<ExtendedRequest>();
    const requestId =
      request.requestId || (request.headers[HTTP_HEADERS.REQUEST_ID] as string) || '';

    return next.handle().pipe(
      map((data) => {
        // If data is already an envelope, return directly
        if (data && typeof data === 'object' && 'success' in data) {
          return data;
        }

        // If data has pagination meta
        if (data && typeof data === 'object' && 'items' in data && 'meta' in data) {
          const { items, meta } = data;
          return {
            success: true,
            data: items,
            meta: {
              requestId,
              timestamp: new Date().toISOString(),
              ...meta,
            },
          };
        }

        return {
          success: true,
          data,
          meta: {
            requestId,
            timestamp: new Date().toISOString(),
          },
        };
      }),
    );
  }
}
