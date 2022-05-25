import express from 'express'

import {  forgetPass } from '../controllers/user'

const router = express.Router()

//route: /api/v1/forgetP/forgetpass/:token
router.post('/:token', forgetPass)


export default router
