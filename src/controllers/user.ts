import { Request, Response, NextFunction } from 'express'
import bcrypt from 'bcrypt-nodejs'
import jwt from 'jsonwebtoken'

import User from '../models/User'
import isEmail from '../helpers/IsEmail'
import UserService from '../services/user'
import {
  BadRequestError,
  InternalServerError,
  NotFoundError,
} from '../helpers/apiError'
import { ADMIN_EMAIL, JWT_SECRET } from '../util/secrets'
import {
  cancellationMail,
  changedPassword,
  resetMail,
  sendWelcomeMessage,
} from '../middlewares/sendEmails'

// POST /a user
export const createUser = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const body = req.body
  if (!body.password) {
    res.json({ error: 'Password required' })
  }
  try {
    const salt1 = bcrypt.genSaltSync(10)
    const passwordHash = await bcrypt.hashSync(req.body.password, salt1)

    const { username, email, googleId } = req.body
    const user = new User({
      username,
      password: passwordHash,
      email,
      joinedDate: new Date(),
      googleId,
      isAdmin: email === ADMIN_EMAIL ? true : false,
    })

    if (isEmail(user.email)) {
      await UserService.create(user)
      const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
        expiresIn: 3600, // expires in 1 hour
      })
      res.status(200).json({ token, user })
      await sendWelcomeMessage(user.email, user.username)
     
    } else {
      res.json({ message: 'invalid email' })
    }
  } catch (error) {
    if (error.name === 'ValidationError') {
      next(new BadRequestError('Invalid Request', error))
    } else {
      next(new InternalServerError('Internal Server Error', error))
    }
  }
}

// GET /all/users
export const findAll = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    res.json(await UserService.findAll())
  } catch (error) {
    next(new NotFoundError('Users not found', error))
  }
}

// GET /user/:userId
export const findById = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    res.json(await UserService.findById(req.params.userId))
  } catch (error) {
    next(new NotFoundError('User not found', error))
  }
}

// PUT /user/:userId
export const updateUser = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const update = req.body
    const userId = req.params.userId
    const updatedUser = await UserService.update(userId, update)
    res.json(updatedUser)
  } catch (error) {
    next(new NotFoundError('User not found', error))
  }
}
// DELETE /user/:userId
export const deleteUser = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const user = await UserService.findById(req.params.userId)

    await UserService.deleteUser(req.params.userId)
    await cancellationMail(user.email, user.username)
    res.status(204).json({ message: 'Successfully, deleted!' })
  } catch (error) {
    next(new NotFoundError('User not found', error))
  }
}

type DecodedToken = {
  userId: string;
}
export const forgetPass = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { password } = req.body
    const { token } = req.params
    const decoded = jwt.verify(token, JWT_SECRET) as DecodedToken
    const userId = decoded.userId
    const salt1 = bcrypt.genSaltSync(10)
    const hash = bcrypt.hashSync(password, salt1)
    await UserService.resetPass(userId, hash)
    res.send(200)
  } catch (e) {
    return next(new Error(e))
  }
}

// forget Password
export const changePass = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { email, username } = req.body
    const user = await UserService.findByEmail(email)
    console.log(user)
    if (user) {
      const userToken = {
        email: user.email,
        id: user._id,
      }
      const token = jwt.sign(userToken, JWT_SECRET)
      const resetLink = `${req.protocol}://localhost:3001/api/v1/password/forgetpass/${token}`
      resetMail(email, username, resetLink)
    }
    if (!user) {
      res.send('user not found')
    }
    res.json({ message: 'password reset link has been sent to you' })
  } catch (error) {
    next(new NotFoundError('User not found', error))
  }
}
export type PayloadType = {
  id: string;
}
/**update password */
export const updatePassword = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const { id } = req.user as PayloadType
  const { oldPassword, newPassword } = req.body
  const userInfo = await UserService.findById(id)
  try {
    const passwordPayload = await UserService.updatePassword(id, {
      oldPassword,
      newPassword,
    })
   
    changedPassword(userInfo.email, userInfo.username)
    res.status(200).json(passwordPayload)
  } catch (error) {
    console.log(error)
  }
}
