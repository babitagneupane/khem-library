import { check } from 'express-validator'

export const createUserValidate = [
  check('email', 'Valid email required').isEmail(),
]
