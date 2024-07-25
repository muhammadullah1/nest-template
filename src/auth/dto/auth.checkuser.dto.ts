import { IsNotEmpty } from 'class-validator';

export class AuthCheckUserDto {
  @IsNotEmpty()
  token: string;
}