import { Request } from 'express'

const tokenExtract = (req: Request) => {
  const authorization = req.get('authorization')
  if (authorization && authorization.toLowerCase().startsWith('bearer')) {
    return authorization.substring(7)
  }
  return null
}

export default tokenExtract