import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Request,
  Post,
  UseGuards,
  Patch,
  Delete,
  SerializeOptions,
  HttpException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthEmailLoginDto } from './dto/auth-email-login.dto';
import { AuthUpdateDto } from './dto/auth-update.dto';
import { AuthGuard } from '@nestjs/passport';
import { CreatePasswordDto } from './dto/auth.createpassword.dto';
import { UsersService } from 'src/users/users.service';
import { SignupOtpDto } from 'src/otp/dto/signup.otp.dto';
import { AuthCheckUserDto } from './dto/auth.checkuser.dto';

@ApiTags('Auth')
@Controller({
  path: 'auth',
})
export class AuthController {
  constructor(
    public service: AuthService,
    private readonly usersService: UsersService,
    private readonly otpService: OtpService,

  ) { }

  @SerializeOptions({
    groups: ['user'],
  })
  @Post('user/login')
  @HttpCode(HttpStatus.OK)
  public async login(@Body() loginDto: AuthEmailLoginDto) {
    return this.service.validateUser(loginDto);
  }

  // user otp login
  @Post('adminotplogin')
  @HttpCode(HttpStatus.OK)
  public async adminValidateOtptLogin(@Body() otpDto: CreateOtpDto) {
    // check otp is admin one or not
    const checkUserrole = await this.service.identifyUser(otpDto.code);
    if (checkUserrole.role === 1) {
      return this.service.validateOtp(otpDto.code);
    } else {
      throw new HttpException('You are not admin', HttpStatus.BAD_REQUEST);
    }
  }

  @Post('customerotplogin')
  @HttpCode(HttpStatus.OK)
  public async customerValidateOtptLogin(@Body() otpDto: CreateOtpDto) {
    const checkUserrole = await this.service.identifyUser(otpDto.code);
    if (checkUserrole.role === 2) {
      return this.service.validateOtp(otpDto.code);
    } else {
      throw new HttpException('You are not customer', HttpStatus.BAD_REQUEST);
    }
  }

  // otp validation for signup
  @SerializeOptions({
    groups: ['users, admin'],
  })
  @Post('user/validatesingupotp')
  @HttpCode(HttpStatus.OK)
  public async userValidateOtpForRegister(@Body() otpDto: SignupOtpDto) {
    const otpData = await this.otpService.checkOtp(otpDto.code);
    if (otpData && otpData.email === otpDto.email) {
      return {
        isValidate: true,
        email: otpData.email,
      }
    } else {
      return {
        isValidate: false,
        message: 'Username not found',
      }
    }
  }

  // user create password after signup
  @SerializeOptions({
    groups: ['users, admin'],
  })
  @Post('user/createpassword')
  @HttpCode(HttpStatus.OK)
  public async userCreatePasswordAfterSignup(@Body() createPasswordDto: CreatePasswordDto) {
    const user = await this.usersService.findOne({
      email: createPasswordDto.email,
    });
    if (user) {
      return await this.usersService.createPasswordAfterSignup(createPasswordDto);
    }
    else {
      return { message: 'User not found' };
    }
  }

  // admin login
  @SerializeOptions({
    groups: ['admin'],
  })
  @Post('admin/login')
  @HttpCode(HttpStatus.OK)
  public async adminLogin(@Body() loginDTO: AuthEmailLoginDto) {
    return this.service.validateLogin(loginDTO, true);
  }

  // admin otp login
  // @SerializeOptions({
  //   groups: ['admin'],
  // })
  // @Post('admin/otplogin')
  // @HttpCode(HttpStatus.OK)
  // public async adminValidateOtptLogin(@Body() otpDto: CreateOtpDto) {
  //   return this.service.validateOtp(otpDto.code);
  // }

  // @Post('email/register')
  // @HttpCode(HttpStatus.CREATED)
  // async register(@Body() createUserDto: AuthRegisterLoginDto) {
  //   return this.service.register(createUserDto);
  // }

  @Post('email/confirm')
  @HttpCode(HttpStatus.OK)
  async confirmEmail(@Body() confirmEmailDto: AuthConfirmEmailDto) {
    return await this.service.confirmEmail(confirmEmailDto.hash);
  }

  @Post('forgot/password')
  @HttpCode(HttpStatus.OK)
  async forgotPassword(@Body() forgotPasswordDto: AuthForgotPasswordDto) {
    return await this.service.forgotPassword(forgotPasswordDto.email);
  }

  @Post('reset/password')
  @HttpCode(HttpStatus.OK)
  async resetPassword(@Body() resetPasswordDto: AuthResetPasswordDto) {
    return await this.service.resetPassword(
      resetPasswordDto.hash,
      resetPasswordDto.password,
    );
  }

  @ApiBearerAuth()
  @SerializeOptions({
    groups: ['user'],
  })
  @Get('me')
  @UseGuards(AuthGuard('jwt'))
  @HttpCode(HttpStatus.OK)
  public async me(@Request() request) {
    return await this.service.me(request.user);
  }

  @ApiBearerAuth()
  @SerializeOptions({
    groups: ['user'],
  })
  @Patch('resetpassword')
  @UseGuards(AuthGuard('jwt'))
  @HttpCode(HttpStatus.OK)
  public async update(@Request() request, @Body() userDto: AuthUpdateDto) {
    return await this.service.update(request.user, userDto);
  }

  @ApiBearerAuth()
  @Delete('me')
  @UseGuards(AuthGuard('jwt'))
  @HttpCode(HttpStatus.OK)
  public async delete(@Request() request) {
    return await this.service.softDelete(request.user);
  }

  // customer create password after signup
  @Post('createpassword')
  @HttpCode(HttpStatus.CREATED)
  async createPassword(@Body() password: CreatePasswordDto) {
    // const user = await this.usersService.findOne({
    //   username: password.username,
    // });
    // if (!user) {
    //   throw new HttpException(
    //     'Username does not exist',
    //     HttpStatus.NOT_FOUND,
    //   );
    // }
    const createdUser = await this.usersService.createPasswordAfterSignup(password);
    if (createdUser.success) {
      return {
        success: true,
        message: 'password crated successfully',
      }
    } else {
      throw new HttpException(
        'usename not found',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  // resend otp
  @Post('resendotp')
  @HttpCode(HttpStatus.OK)
  async resendOtp(@Body() username: any) {
    return await this.service.resendOtp(username);
  }

  // check user validation by passing token
  @Post('validateuser')
  @HttpCode(HttpStatus.OK)
  async checkUser(@Body() token: AuthCheckUserDto) {
    console.log('===============================================================')
    console.log(token)
    return await this.service.checkValidation(token);
  }

}
