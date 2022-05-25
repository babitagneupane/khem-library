import { Request, Response, NextFunction } from 'express'
import bcrypt from 'bcrypt-nodejs'
import jwt from 'jsonwebtoken'

import { JWT_SECRET } from '../util/secrets'
import User, { UserDocument } from '../models/User'

export const createLogin = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const user = await User.findOne({ email: req.body.email })
    const passwordCorrect =
      user === null
        ? false
        : await bcrypt.compareSync(req.body.password, user.password)
    if (!(user && passwordCorrect)) {
      res.json({ error: 'username or password incorrect' })
      return
    }
    if(!passwordCorrect){
      res.json({error:'password does not match!'})
    }
    const userInfo = {
      username: user.username,
      email: user.email,
      id: user.id,
    }
    const token = jwt.sign(userInfo, JWT_SECRET, {
      expiresIn: 3600,
    })
    //res.cookie('Cookies', token)
    res.status(200).json({ token, userInfo })
  } catch (error) {
    next(error)
  }
}
export const googleLogin = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const user = req.user as UserDocument
    console.log('hi from googleLogin', user)
    
    if (user) {
      const userInfo = {
        username: user.username,
        email: user.email,
        id: user.id,
      }
      const token = jwt.sign({userInfo}, JWT_SECRET, {
        expiresIn: 3600,
      })
      res.status(200).json({ token, userInfo })  
      //res.cookie('Cookies', token)
      //res.redirect('http://localhost:3000')
    }else{
      res.json({ error: 'username or password incorrect' })
      return
    }
  } catch (error) {
    next(error)
  }
}
