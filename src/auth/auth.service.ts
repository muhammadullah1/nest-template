import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Users } from '../users/entities/user.entity';
import * as bcrypt from 'bcryptjs';
import { AuthEmailLoginDto } from './dto/auth-email-login.dto';
import { AuthUpdateDto } from './dto/auth-update.dto';
import { randomStringGenerator } from '@nestjs/common/utils/random-string-generator.util';
import { RoleEnum } from 'src/roles/roles.enum';
import { StatusEnum } from 'src/statuses/statuses.enum';
import * as crypto from 'crypto';
import { Status } from 'src/statuses/entities/status.entity';
// import { Role } from 'src/roles/entities/role.entity';
import { AuthProvidersEnum } from './auth-providers.enum';
import { UsersService } from 'src/users/users.service';
import { ForgotService } from 'src/forgot/forgot.service';
import { MailService } from 'src/mail/mail.service';
import { plainToClass } from 'class-transformer';
import { generateOTP } from 'src/utils/generaterandom/generateRandom';
import { OtpService } from 'src/otp/otp.service';
import { CustomerService } from 'src/customer/customer.service';
import { AuthCheckUserDto } from './dto/auth.checkuser.dto';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private usersService: UsersService,
    private customerService: CustomerService,
    private forgotService: ForgotService,
    private mailService: MailService,
    private otpService: OtpService,
  ) { }

  async validateLogin(
    loginDto: AuthEmailLoginDto,
    onlyAdmin: boolean,
  ): Promise<{ isValidate: boolean; otp: string }> {
    // check loginDto.username is email or mobile
    const isEmail = loginDto.username.includes('@');
    const user = await this.usersService.findOneWithRelations(
      isEmail ? { email: loginDto.username } : { mobile: loginDto.username },
    );
    if (
      !user ||
      (user &&
        !(onlyAdmin ? [RoleEnum.admin] : [RoleEnum.user]).includes(
          user.role.id,
        ))
    ) {
      throw new HttpException(
        {
          status: HttpStatus.UNPROCESSABLE_ENTITY,
          errors: {
            username: 'notFound',
          },
        },
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }

    if (user.provider !== AuthProvidersEnum.email) {
      throw new HttpException(
        {
          status: HttpStatus.UNPROCESSABLE_ENTITY,
          errors: {
            email: `needLoginViaProvider:${user.provider}`,
          },
        },
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }

    const isValidPassword = await bcrypt.compare(
      loginDto.password,
      user.password,
    );
    if (isValidPassword) {
      // save otp in database
      const otp = generateOTP();
      await this.otpService.saveOtp(
        otp,
        user.email,
        user.id,
        user.mobile,
      );
      // check user is admin or not
      if (user.role.id === RoleEnum.admin) {
        // check username is email or phonenumber to send otp to admin
        if (isEmail) {
          // send otp mail to admin
          // await this.mailService.loginOtp({
          //   to: user.email,
          //   data: {
          //     otp,
          //   },
          // });
          console.log('send mail to admin are commented opt: ', otp, user.email);
        } else {
          // send otp to admin via phone number
          // await this.otpService.sendSMS(otp, user.mobile);
          console.log('send sms to admin are commented opt: ', otp, user.mobile)
        }
      } else {
        // send otp mail to user
        // await this.otpService.sendSMS(otp, user.customer.mobile);
        console.log('send sms to user are commented opt: ', otp, user.mobile)
      }
      return {
        isValidate: true,
        otp: user.role.id === RoleEnum.admin ? 'OTP sent to mail' : 'OTP sent to your mobile number'
      }

    } else {
      throw new HttpException(
        {
          status: HttpStatus.UNPROCESSABLE_ENTITY,
          errors: {
            password: 'incorrectPassword',
          },
        },
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }
  }


  async validateUser(loginDto: AuthEmailLoginDto) {
    const isEmail = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(loginDto.username);
    const isCnic = /^\d{14}$/.test(loginDto.username);
    const isFileNumber = /^[a-zA-Z0-9]{6}$/.test(loginDto.username);

    let data = {};
    switch (true) {
      case isEmail:
        data = { email: loginDto.username };
        break;
      case isCnic:
        data = { cnic: loginDto.username };
        break;
      case isFileNumber:
        data = { plots: loginDto.username };
        break;
      default:
        throw new HttpException(
          {
            status: HttpStatus.UNPROCESSABLE_ENTITY,
            errors: {
              username: 'notFound, please enter valid email, cnic or file number',
            },
          },
          HttpStatus.UNPROCESSABLE_ENTITY,
        );
    };
    let user = null;
    if (isEmail) {
      user = await this.usersService.findOneWithRelations(data);
      console.log('servicrs----------', data, user)

    } else {
      user = await this.customerService.findOne(data);
      user = user.user;
    }
    if (
      !user ||
      (user &&
        !([RoleEnum.user]).includes(
          user.role.id,
        ))
    ) {
      throw new HttpException(
        {
          status: HttpStatus.UNPROCESSABLE_ENTITY,
          errors: {
            username: 'notFound',
          },
        },
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }

    if (user.provider !== AuthProvidersEnum.email) {
      throw new HttpException(
        {
          status: HttpStatus.UNPROCESSABLE_ENTITY,
          errors: {
            email: `needLoginViaProvider:${user.provider}`,
          },
        },
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }

    const isValidPassword = await bcrypt.compare(
      loginDto.password,
      user.password,
    );
    if (isValidPassword) {
      // save otp in database
      const otp = generateOTP();
      await this.otpService.saveOtp(
        otp,
        user.email,
        user.id,
        user.mobile,
      );
      // send otp mail to user
      // await this.otpService.sendSMS(otp, user.customer.mobile);
      console.log('send sms to user are commented opt: ', otp, user.mobile)

      return {
        isValidate: true,
        otp: user.role.id === RoleEnum.admin ? 'sent to mail' : 'sent to your mobile number'
      }

    } else {
      throw new HttpException(
        {
          status: HttpStatus.UNPROCESSABLE_ENTITY,
          errors: {
            password: 'incorrectPassword',
          },
        },
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }
  }

  async validateOtp(otp: string): Promise<{ token: string }> {
    const otpData = await this.otpService.findOtp(otp);
    if (otpData) {
      const token = await this.jwtService.signAsync({
        id: otpData.user.id,
        role: otpData.user.role.id,
        email: otpData.email,
      });
      return {
        token: token,
      }
    } else {
      throw new HttpException(
        {
          status: HttpStatus.UNPROCESSABLE_ENTITY,
          errors: {
            otp: 'incorrectOtp, used or expired',
          },
        },
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }
  }

  // identify user role based on otp
  async identifyUser(otp: string): Promise<{ role: any }> {
    const otpData = await this.otpService.checkOtp(otp);
    if (otpData) {
      return {
        role: otpData.user.role.id,
      }
    } else {
      throw new HttpException(
        {
          status: HttpStatus.NOT_FOUND,
          error: `otp is incorrect or expired`,
        },
        HttpStatus.NOT_FOUND,
      );
    }
  }


  async confirmEmail(hash: string): Promise<void> {
    const user = await this.usersService.findOne({
      hash,
    });
    if (!user) {
      throw new HttpException(
        {
          status: HttpStatus.NOT_FOUND,
          error: `notFound`,
        },
        HttpStatus.NOT_FOUND,
      );
    }
    user.hash = null;
    user.status = plainToClass(Status, {
      id: StatusEnum.active,
    });
    await user.save();
  }

  async forgotPassword(email: string): Promise<object> {
    const user = await this.usersService.findOne({
      email: email,
    });
    if (!user) {
      throw new HttpException(
        {
          status: HttpStatus.UNPROCESSABLE_ENTITY,
          errors: {
            email: 'emailNotExists',
          },
        },
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    } else {
      const hash = crypto
        .createHash('sha256')
        .update(randomStringGenerator())
        .digest('hex');
      await this.forgotService.create({
        hash,
        user,
      });
      await this.mailService.forgotPassword({
        to: email,
        data: {
          hash,
        },
      });

      return {
        isValidate: true,
        message: 'key sent to your mail'
      }
    }
  }

  async resetPassword(hash: string, password: string): Promise<object> {
    const forgot = await this.forgotService.findOne({
      where: {
        hash,
      },
    });
    if (!forgot) {
      throw new HttpException(
        {
          status: HttpStatus.UNPROCESSABLE_ENTITY,
          errors: {
            hash: `notFound`,
          },
        },
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }

    const user = forgot.user;
    user.password = password;
    await user.save();
    await this.forgotService.softDelete(forgot.id);
    return {
      isValidate: true,
      message: 'password reset successfully'
    }
  }

  async me(user: Users): Promise<Users> {
    return this.usersService.findOne({
      id: user.id,
    });
  }

  async update(user: Users, userDto: AuthUpdateDto): Promise<object> {
    if (userDto.password) {
      if (userDto.oldPassword) {
        const currentUser = await this.usersService.findOne({
          id: user.id,
        });
        const isValidOldPassword = await bcrypt.compare(
          userDto.oldPassword,
          currentUser.password,
        );
        if (isValidOldPassword) {
          // save password 
          currentUser.password = userDto.password;
          await currentUser.save();
          return {
            success: true,
            message: 'password updated successfully'
          }

        } else {
        throw new HttpException(
          {
            status: HttpStatus.UNPROCESSABLE_ENTITY,
            errors: {
              oldPassword: 'incorrectOldPassword',
            },
          },
          HttpStatus.UNPROCESSABLE_ENTITY,
        );
      }
    }
  }

    // return this.usersService.findOne({
    //   id: user.id,
    // });

  }

  // resend otp
  async resendOtp(username): Promise<object> {
    // usernam is email or mobile
    const isEmail = username.username.includes('@');
    const user = await this.usersService.findOneWithRelations(
      isEmail ? { email: username.username } : { mobile: username.username },
    );
    if (!user) {
      throw new HttpException(
        {
          status: HttpStatus.UNPROCESSABLE_ENTITY,
          errors: {
            username: 'userNotFound',
          },
        },
        HttpStatus.UNPROCESSABLE_ENTITY,
      );
    }
    // save otp in database
    const otp = generateOTP();
    await this.otpService.saveOtp(
      otp,
      user.email,
      user.id,
      user.mobile,
    );
    // check mail or mobile to send otp
    if (isEmail) {
      console.log('send email to user are commented opt: ', otp, user.email)
      await this.mailService.loginOtp({
        to: user.email,
        data: {
          otp,
        },
      });
    } else {
      console.log('send sms to user are commented opt: ', otp, user.mobile)
      // await this.otpService.sendSMS(otp, user.mobile)
    }
    return {
      isValidate: true,
      message: `otp sent to ${isEmail ? 'email' : 'mobile'}`,
    }
  }

  async softDelete(user: Users): Promise<void> {
    await this.usersService.softDelete(user.id);
  }

  // check validation by calling this api at every page load by passing user token
  async checkValidation(token: AuthCheckUserDto): Promise<object> {
    // get id from token
    // handle invalid token
    try {
      const userId = await this.jwtService.verify(token.token);
      const userDetail = await this.usersService.findOneWithRelations({
        id: userId.id
      });
      if (userDetail.status.id === StatusEnum.active) {
        return {
          isValidate: true,
          message: 'user is active'
        }
      } else {
        return {
          isValidate: false,
          message: 'user is not active'
        }
      }
    } catch (error) {
      return {
        isValidate: false,
        message: 'invalid token'
      }
    }
  }

}
