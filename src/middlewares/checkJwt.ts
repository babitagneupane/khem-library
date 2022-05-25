import { Request, Response, NextFunction } from 'express'
import jwt from 'jsonwebtoken'

import { UnauthorizedError } from '../helpers/apiError'
import { JWT_SECRET } from '../util/secrets'

export const checkJwt = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  let decoded
  try {
    const token = (req.headers['authorization'] || '').split(' ')[1]
    decoded = await jwt.verify(token, JWT_SECRET)
    req.user = decoded
  } catch (error) {
    next(new UnauthorizedError())
    return
  }
  const newToken = jwt.sign({ decoded }, JWT_SECRET, {
    expiresIn: '1h',
  })
  res.setHeader('token', newToken)
  next()
}
