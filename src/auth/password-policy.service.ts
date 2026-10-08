import { BadRequestException, Injectable } from '@nestjs/common';
import zxcvbn from 'zxcvbn';

const MAX_PASSWORD_LENGTH = 128;
// zxcvbn es superlineal en longitud: acotamos la entrada para evitar DoS.
const ZXCVBN_INPUT_LIMIT = 100;

/**
 * Política de contraseñas complementaria al validador del DTO
 * (IsStrongPassword) - NIST CSF PR.AA-03 (fuerza mínima de credenciales).
 *
 * Usa zxcvbn para rechazar contraseñas débiles/predicibles que cumplen la
 * regla de complejidad superficial (p. ej. "Password1!2026").
 */
@Injectable()
export class PasswordPolicyService {
  assert(password: string, email?: string): void {
    if (password.length > MAX_PASSWORD_LENGTH) {
      throw new BadRequestException(
        `La contraseña no puede exceder ${MAX_PASSWORD_LENGTH} caracteres`,
      );
    }

    const context: string[] = [];
    if (email) {
      const [localPart = '', domain = ''] = email.split('@');
      context.push(email, localPart, domain);
    }

    const result = zxcvbn(password.slice(0, ZXCVBN_INPUT_LIMIT), context);

    if (result.score < 3) {
      throw new BadRequestException(
        'La contraseña es demasiado débil. Use una frase larga y poco predecible.',
      );
    }
  }
}
