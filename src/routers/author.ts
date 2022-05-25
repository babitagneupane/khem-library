import express from 'express'

import { checkJwt } from '../middlewares/checkJwt'

import {
  createAuthor,
  findAll,
  findById,
  deleteAuthor,
  updateAuthor,
} from '../controllers/author'

const router = express.Router()
// Every path we define here will get /api/v1/authors prefix
router.get('/', findAll)
router.post('/', checkJwt, createAuthor)
router.get('/:authorId', findById)
router.delete('/:authorId', checkJwt, deleteAuthor)
router.put('/:authorId', checkJwt, updateAuthor)

export default router
