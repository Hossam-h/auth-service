import { Controller, Post, Body, Get, Headers } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Post('login')
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }

  // Endpoint داخلي - الـ Gateway بيكلمه عشان يتحقق من الـ Token
  @Get('validate')
  validate(@Headers('authorization') auth: string) {
    const token = auth?.replace('Bearer ', '');
    return this.authService.validateToken(token);
  }
}