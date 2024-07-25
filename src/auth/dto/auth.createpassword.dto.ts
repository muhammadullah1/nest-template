import { IsEmail, IsNotEmpty } from 'class-validator';
import { Match } from 'src/utils/match.decorator';

export class CreatePasswordDto {
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  password: string;

  @IsNotEmpty()
  // check if the password and confirm password are the same
  @Match('password')
  confirmpassword: string;
}


