import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { RegisterUserDto, LoginUserDto } from './dto';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
	private readonly logger = new Logger(AuthService.name);

	constructor(private jwtService: JwtService) {
		super();
	}

	onModuleInit() {
		this.$connect();
		this.logger.log('MongoDB connected');
	}

	async registerUser(registerUserDto: RegisterUserDto) {
		const { email, name, password } = registerUserDto;

		try {
			const user = await this.user.findUnique({
				where: { email },
			});

			if (user) {
				throw new RpcException({
					status: HttpStatus.BAD_REQUEST,
					message: 'User already exists',
				});
			}

			const newUser = await this.user.create({
				data: {
					email: email,
					password: bcrypt.hashSync(password, 10),
					name: name,
				},
			});

			const { password: _, ...rest } = newUser;

			return {
				user: rest,
				token: await this.signJWT(rest),
			};
		} catch (error) {
			throw new RpcException({
				status: HttpStatus.BAD_REQUEST,
				message: error.message,
			});
		}
	}

	async loginUser(loginUserDto: LoginUserDto) {
		const { email, password } = loginUserDto;

		try {
			const user = await this.user.findUnique({
				where: { email },
			});

			if (!user) {
				throw new RpcException({
					status: HttpStatus.BAD_REQUEST,
					message: 'User/Password not valid - email',
				});
			}

			const isPasswordValid = bcrypt.compareSync(password, user.password);

			if (!isPasswordValid) {
				throw new RpcException({
					status: HttpStatus.BAD_REQUEST,
					message: 'User/Password not valid - password',
				});
			}

			const { password: _, ...rest } = user;

			return {
				user: rest,
				token: await this.signJWT(rest),
			};
		} catch (error) {
			throw new RpcException({
				status: HttpStatus.BAD_REQUEST,
				message: error.message,
			});
		}
	}

	async signJWT(payload: JwtPayload) {
		return this.jwtService.sign(payload);
	}

	async verifyToken(token: string) {
		try {
			const { exp, iat, ...user } = this.jwtService.verify(token, {
				secret: envs.jwtSecret,
			});

			return { user, token: await this.signJWT(user) };
		} catch (error) {
			this.logger.error(error);
			throw new RpcException({
				status: HttpStatus.UNAUTHORIZED,
				message: 'Invalid Token',
			});
		}
	}
}
