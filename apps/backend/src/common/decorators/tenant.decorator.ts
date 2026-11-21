import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { TenantRequest } from '../middleware/tenant.middleware';
import { TenantContext } from '@dcmp/shared-types';

export const CurrentTenant = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): TenantContext | undefined => {
    const request = ctx.switchToHttp().getRequest<TenantRequest>();
    return request.tenant;
  },
);

export const CurrentUser = createParamDecorator((_data: unknown, ctx: ExecutionContext) => {
  const request = ctx.switchToHttp().getRequest();
  return request.user;
});
