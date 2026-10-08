import { Transform } from 'class-transformer';
import {
  IsEmail,
  IsNotEmpty,
  IsString,
  IsStrongPassword,
  MaxLength,
  MinLength,
} from 'class-validator';

const lowercaseEmail = ({ value }: { value: unknown }): unknown =>
  typeof value === 'string' ? value.trim().toLowerCase() : value;

export class RegisterDto {
  @Transform(lowercaseEmail)
  @IsEmail({}, { message: 'El correo electrónico no es válido' })
  @MaxLength(254, { message: 'El correo electrónico es demasiado largo' })
  email!: string;

  @IsString({ message: 'La contraseña debe ser una cadena de texto' })
  @MinLength(12, { message: 'La contraseña debe tener al menos 12 caracteres' })
  @MaxLength(128, { message: 'La contraseña no puede exceder 128 caracteres' })
  @IsStrongPassword(
    {
      minLength: 12,
      minLowercase: 1,
      minUppercase: 1,
      minNumbers: 1,
      minSymbols: 1,
    },
    {
      message:
        'La contraseña debe contener mayúsculas, minúsculas, números y símbolos',
    },
  )
  password!: string;
}

export class LoginDto {
  @Transform(lowercaseEmail)
  @IsEmail({}, { message: 'El correo electrónico no es válido' })
  @MaxLength(254, { message: 'El correo electrónico es demasiado largo' })
  email!: string;

  @IsString({ message: 'La contraseña debe ser una cadena de texto' })
  @IsNotEmpty({ message: 'La contraseña es obligatoria' })
  @MaxLength(128, {
    message: 'La contraseña no puede exceder 128 caracteres',
  })
  password!: string;
}
