import { IsEmail, Validate, IsStrongPassword } from 'class-validator';
import { IsNotExist } from 'src/utils/validators/is-not-exists.validator';
import { Transform } from 'class-transformer';

export class AuthRegisterDto {
  @Transform(({ value }) => value.toLowerCase().trim())
  @Validate(IsNotExist, ['Users'], {
    message: 'emailAlreadyExists',
  })
  @IsEmail()
  email: string;

  @IsStrongPassword({
    minLength: 8,
    minNumbers: 1,
    minUppercase: 1,
    minLowercase: 1,
    minSymbols: 1,
  })
  password: string;

  fullname: string;
}
