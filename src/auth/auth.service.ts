import {
  BadRequestException,
  Inject,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { Repository } from 'typeorm';

import { User } from './entities/user.entity';
import { CreateUserDto, LoginUserDto } from './dto';
import { JwtPayload } from './interfaces/jwt-payload.interface';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,

    private readonly jwtService: JwtService,
  ) {}

  async create(createUserDto: CreateUserDto) {
    try {
      const { password, ...userData } = createUserDto;

      const user = this.userRepository.create({
        ...userData,
        password: bcrypt.hashSync(password, 10),
      });

      await this.userRepository.save(user);

      delete user.password;

      return {
        ...user,
        token: this.getJwtToken({ id: user.id }),
      };
    } catch (error) {
      this.handleDbErrors(error);
    }
  }

  async login(loginUserDto: LoginUserDto) {
    try {
      const { email, password } = loginUserDto;
      const candidate = await this.userRepository.findOne({
        where: { email },
        select: { email: true, password: true, id: true },
      });

      if (!candidate)
        throw new UnauthorizedException('Invalid credentials -- dev email');

      if (!bcrypt.compareSync(password, candidate.password))
        throw new UnauthorizedException('Invalid credentials -- dev password');

      delete candidate.password;

      return {
        ...candidate,
        token: this.getJwtToken({ id: candidate.id }),
      };
    } catch (error) {
      console.log(error);
      this.handleDbErrors(error);
    }
  }

  async checkAuthStatus(user: User) {
    return {
      ...user,
      token: this.getJwtToken({id: user.id})
    }
  }

  private getJwtToken(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  private handleDbErrors(error: any): never {
    console.log(error);
    if (error.code === '23505') throw new BadRequestException(error.detail);

    if (error.status === 401) throw new UnauthorizedException(error.message);

    throw new InternalServerErrorException('Please check the server logs.');
  }
}
