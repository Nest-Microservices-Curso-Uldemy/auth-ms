import { IsEmail, IsString, IsStrongPassword } from 'class-validator';

export class RegisterUserDto {
	@IsString()
	public name: string;

	@IsString()
	@IsEmail()
	public email: string;

	@IsString()
	@IsStrongPassword()
	public password: string;
}
