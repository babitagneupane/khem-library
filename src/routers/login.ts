import express from 'express'
import passport from 'passport'
import { checkJwt } from '../middlewares/checkJwt'

import { createLogin, googleLogin } from '../controllers/login'

const router = express.Router()
router.post('/', createLogin)

router.get('/isAuthenticated', checkJwt)
router.get(
  '/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
  })
)
router.get('/google/callback', passport.authenticate('google'), googleLogin)
export default router
