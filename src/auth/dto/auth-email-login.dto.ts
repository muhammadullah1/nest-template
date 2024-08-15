import { IsNotEmpty, IsOptional } from 'class-validator';
import { Transform } from 'class-transformer';
import { lowerCaseTransformer } from '../../utils/transformers/lower-case.transformer';

export class AuthEmailLoginDto {
  @Transform(lowerCaseTransformer)
  @IsNotEmpty()
  @IsOptional()
  email: string;

  @IsNotEmpty()
  password: string;
}

