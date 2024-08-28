import { Controller } from '@nestjs/common';
import { AuthService } from './auth.service';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { RegisterUserDto, LoginUserDto } from './dto';

@Controller()
export class AuthController {
	constructor(private readonly authService: AuthService) {}

	@MessagePattern({ cmd: 'auth.register.user' })
	registerUser(@Payload() registerUserDto: RegisterUserDto) {
		return this.authService.registerUser(registerUserDto);
	}

	@MessagePattern({ cmd: 'auth.login.user' })
	loginUser(@Payload() loginUserDto: LoginUserDto) {
		return this.authService.loginUser(loginUserDto);
	}

	@MessagePattern({ cmd: 'auth.verify.user' })
	verifyToken(@Payload() token: string) {
		return this.authService.verifyToken(token);
	}
}
