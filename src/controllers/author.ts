import { Request, Response, NextFunction } from 'express'

import isAdminEmail from '../helpers/isAdminEmail'
import AuthorService from '../services/author'
import Author from '../models/Author'
import {
  NotFoundError,
  BadRequestError,
  InternalServerError,
} from '../helpers/apiError'

// POST /an author
export const createAuthor = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { firstName, lastName, email, dob } = req.body
    const author = new Author({ firstName, lastName, email, dob })
    if (isAdminEmail(req)) {
      await AuthorService.create(author)
      res.json(author)
    } else {
      res.json({ message: 'Not allowed to create author' })
    }
  } catch (error) {
    if (error.name === 'ValidationError') {
      next(new BadRequestError('Invalid Request', error))
    } else {
      next(new InternalServerError('Internal Server Error', error))
    }
  }
}
// GET /author/:authorId
export const findById = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    res.json(await AuthorService.findById(req.params.authorId))
  } catch (error) {
    next(new NotFoundError('Author not found', error))
  }
}
// GET /all/authors
export const findAll = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    res.json(await AuthorService.findAll())
  } catch (error) {
    next(new NotFoundError('Movies not found', error))
  }
}
// DELETE /author/:authorId
export const deleteAuthor = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    if (isAdminEmail(req)) {
      await AuthorService.deleteAuthor(req.params.authorId)
      res.status(204).end()
    } else {
      res.json({ message: 'Not allowed to delete author' })
    }
  } catch (error) {
    next(new NotFoundError('Author not found', error))
  }
}
// PUT /author/:authorId
export const updateAuthor = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const update = req.body
    const authorId = req.params.authorId
    if (isAdminEmail(req)) {
      const updatedAuthor = await AuthorService.update(authorId, update)
      res.json(updatedAuthor)
    } else {
      res.json({ message: 'Not allowed to update author' })
    }
  } catch (error) {
    next(new NotFoundError('Author not found', error))
  }
}
