import { Request } from 'express'

import { ADMIN_EMAIL } from '../util/secrets'

type ReqUser = {
  username: string;
  email: string;
}
export default function isAdminEmail(req: Request): boolean {
  const reqUser = req.user as ReqUser
  return reqUser.email === ADMIN_EMAIL ? true : false
}
