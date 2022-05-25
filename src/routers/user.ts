import express from 'express'

import { checkJwt } from '../middlewares/checkJwt'
import { createUserValidate } from '../middlewares/validateSignup'

import {
  createUser,
  findAll,
  findById,
  updateUser,
  deleteUser,
  updatePassword
} from '../controllers/user'

const router = express.Router()
router.post('/', createUser)
router.get('/', findAll)
router.get('/:userId', findById)
router.put('/:userId', updateUser)
router.delete('/:userId', checkJwt, deleteUser)
router.patch('/changePP/:userId', checkJwt, updatePassword)
export default router
