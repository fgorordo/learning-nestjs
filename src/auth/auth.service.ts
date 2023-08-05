import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { User } from './entities/user.entity';
import { CreateUserDto, LoginUserDto } from './dto';

@Injectable()
export class AuthService {

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>
  ){}

  async create(createUserDto: CreateUserDto) {
    try {

      const {password, ...userData} = createUserDto;

      const user = this.userRepository.create({
        ...userData,
        password: bcrypt.hashSync(password, 10)
      });

      await this.userRepository.save(user)
      
      delete user.password;

      return user;
      //TODO: Return acces jwt;

    } catch (error) {
      this.handleDbErrors(error);
    }
  }

  async login(loginUserDto: LoginUserDto) {
    try {
      
      const { email, password } = loginUserDto;
      const candidate = await this.userRepository.findOne({
        where: {email},
        select: {email: true, password: true}
      });

      if (!candidate)
        throw new UnauthorizedException('Invalid credentials -- dev email');
      
      if (!bcrypt.compareSync(password, candidate.password))
        throw new UnauthorizedException('Invalid credentials -- dev password');
      
      return candidate;
      //TODO: return access jwt

    } catch (error) {
      console.log(error)
      this.handleDbErrors(error);
    }
  }

  private handleDbErrors(error: any): never {
    console.log(error);
    if (error.code === '23505') 
      throw new BadRequestException(error.detail);
      
    if (error.status === 401 ) 
      throw new UnauthorizedException(error.message);

    throw new InternalServerErrorException('Please check the server logs.')
  }
}
