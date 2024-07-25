import { IsNotEmpty, IsOptional } from 'class-validator';
import { Transform } from 'class-transformer';

export class AuthEmailLoginDto {
  @Transform(({ value }) => value.toLowerCase().trim())
  @IsNotEmpty()
  @IsOptional()
  username: string;

  @IsNotEmpty()
  password: string;
}

