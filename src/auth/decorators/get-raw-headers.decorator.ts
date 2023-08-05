import { ExecutionContext, InternalServerErrorException, createParamDecorator } from "@nestjs/common";

export const RawHeaders = createParamDecorator((data:string, ctx: ExecutionContext) => {
    const req = ctx.switchToHttp().getRequest()
    const rawHeaders = req.rawHeaders

    if(!rawHeaders)
        throw new InternalServerErrorException('Headers not found in request')

    return (!data) ? rawHeaders : rawHeaders[data];
})