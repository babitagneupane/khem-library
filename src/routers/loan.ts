import express from 'express'

import { checkJwt } from '../middlewares/checkJwt'
import {
  loanBook,
  findAll,
  findById,
  deleteALoan,
  updateLoan,
} from '../controllers/loan'

// /api/v1/loans/...
const router = express.Router()
router.post('/', checkJwt, loanBook)
router.get('/', findAll)
router.get('/:loanId', findById)
router.delete('/:loanId', checkJwt, deleteALoan)
router.put('/:loanId', checkJwt, updateLoan)

export default router
