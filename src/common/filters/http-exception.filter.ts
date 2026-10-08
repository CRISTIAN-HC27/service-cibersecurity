import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { Logger } from 'nestjs-pino';

/**
 * Filtro global de excepciones.
 *
 * Nunca filtra trazas de pila, mensajes internos de Prisma ni detalles de la
 * base de datos hacia el cliente (PR.DS / ID.RA: reducción de superficie de
 * información). Todo lo interno se registra en el log estructurado.
 */
@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  constructor(private readonly logger: Logger) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let payload: { statusCode: number; message: string | string[]; error?: string } = {
      statusCode: status,
      message: 'Error interno del servidor',
    };

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const body = exception.getResponse();
      if (typeof body === 'string') {
        payload = { statusCode: status, message: body };
      } else if (typeof body === 'object' && body !== null) {
        const raw = body as Record<string, unknown>;
        payload = {
          statusCode: status,
          message: (raw['message'] as string | string[]) ?? exception.message,
          ...(typeof raw['error'] === 'string' ? { error: raw['error'] } : {}),
        };
      }
    } else {
      // Errores del propio Express (body-parser): p.ej. entity.too.large
      // llega como PayloadTooLargeError con `status: 413`.
      const raw = exception as { status?: number; statusCode?: number };
      const rawStatus = raw?.status ?? raw?.statusCode;
      if (
        typeof rawStatus === 'number' &&
        rawStatus >= 400 &&
        rawStatus < 500
      ) {
        status = rawStatus;
        payload = {
          statusCode: status,
          message:
            status === 413
              ? 'Cuerpo de la solicitud demasiado grande'
              : 'Solicitud inválida',
          ...(status === 413
            ? { error: 'Payload Too Large' }
            : { error: 'Bad Request' }),
        };
      }
    }

    if (status >= 500) {
      this.logger.error(
        { err: exception, path: request.url, method: request.method },
        'Excepción no controlada',
      );
    }

    response.status(status).json(payload);
  }
}
