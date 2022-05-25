import express from 'express'

import { changePass } from '../controllers/user'

const router = express.Router()

//route: /api/v1/changepass
router.post('/', changePass)

export default router
