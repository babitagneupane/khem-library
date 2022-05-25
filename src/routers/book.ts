import express from 'express'

import { checkJwt } from '../middlewares/checkJwt'

import {
  createBook,
  findAll,
  findById,
  updateBook,
  deleteBook,
} from '../controllers/book'

const router = express.Router()
// Every path we define here will get /api/v1/books prefix
router.get('/', findAll)
router.post('/', checkJwt, createBook)
router.post('/:bookId', findById)
router.put('/:bookId', checkJwt, updateBook)
router.delete('/:bookId', checkJwt, deleteBook)

export default router
