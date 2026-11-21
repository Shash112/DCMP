import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { HTTP_HEADERS } from '@dcmp/api-contracts';

export interface ExtendedRequest extends Request {
  requestId?: string;
}

@Injectable()
export class RequestIdMiddleware implements NestMiddleware {
  use(req: ExtendedRequest, res: Response, next: NextFunction): void {
    const existingId = req.headers[HTTP_HEADERS.REQUEST_ID] as string;
    const requestId = existingId || uuidv4();
    req.requestId = requestId;
    res.setHeader(HTTP_HEADERS.REQUEST_ID, requestId);
    next();
  }
}
