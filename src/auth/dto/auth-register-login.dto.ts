import { IsEmail, IsNotEmpty, MinLength, Validate } from 'class-validator';
import { IsNotExist } from 'src/utils/validators/is-not-exists.validator';
import { Transform } from 'class-transformer';

export class AuthRegisterLoginDto {
  @Transform(({ value }) => value.toLowerCase().trim())
  @Validate(IsNotExist, ['Users'], {
    message: 'emailAlreadyExists',
  })
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @MinLength(6)
  password: string;

  @IsNotEmpty()
  fullname: string;
}
