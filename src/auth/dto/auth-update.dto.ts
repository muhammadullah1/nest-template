import { IsNotEmpty, Matches } from 'class-validator';
import { Match } from 'src/utils/match.decorator';

export class AuthUpdateDto {
  @IsNotEmpty({ message: 'mustBeNotEmpty' })
  oldPassword: string;

  @IsNotEmpty()
  @Matches(/^(?=.*[A-Z])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{6,}$/, {
    message: 'The password shall have at least 1 upper-case and 1 symbol',
  })
  password: string | null;

  @IsNotEmpty({ message: 'mustBeNotEmpty' })
  @Match('password')
  conformPassword: string;

}


