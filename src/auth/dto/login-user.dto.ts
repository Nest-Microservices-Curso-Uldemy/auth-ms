import { IsEmail, IsString, IsStrongPassword } from 'class-validator';

export class LoginUserDto {
	@IsString()
	@IsEmail()
	public email: string;

	@IsString()
	@IsStrongPassword()
	public password: string;
}
