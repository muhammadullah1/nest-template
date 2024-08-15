import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  SerializeOptions,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthEmailLoginDto } from './dto/auth-email-login.dto';
import { LoginResponseDto } from './dto/login-response.dto';

@Controller({
  path: 'auth',
  version: '1',
})
export class AuthController {
  constructor(private readonly service: AuthService) {}

  // user login
  @SerializeOptions({
    groups: ['me'],
  })
  @Post('email/login')
  @HttpCode(HttpStatus.OK)
  public login(@Body() loginDto: AuthEmailLoginDto): Promise<LoginResponseDto> {
    return this.service.validateLogin(loginDto);
  }
}
