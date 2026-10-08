import { BadRequestException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import { PasswordPolicyService } from './password-policy.service.js';

const policy = new PasswordPolicyService();

describe('política de contraseñas', () => {
  it('acepta una contraseña fuerte', () => {
    expect(() => policy.assert('Tr0p-S3gura!2026')).not.toThrow();
  });

  it('rechaza contraseñas débiles', () => {
    expect(() => policy.assert('password123')).toThrow(BadRequestException);
  });

  it('rechaza contraseñas predecibles aunque cumplan la complejidad', () => {
    expect(() => policy.assert('Password1!2026')).toThrow(
      /demasiado débil/,
    );
  });

  it('usa el email como contexto para detectar contraseñas derivadas del usuario', () => {
    expect(() =>
      policy.assert('Rooney-2026!Admin', 'rooney@test.local'),
    ).not.toThrow();
    // La contraseña contiene el nombre local del email: debe puntuar bajo.
    expect(() =>
      policy.assert('Rooney2026!', 'rooney@test.local'),
    ).toThrow(BadRequestException);
  });

  it('rechaza contraseñas demasiado largas (DoS en hashing)', () => {
    expect(() => policy.assert('Aa1!'.repeat(60))).toThrow(/128/);
  });
});
