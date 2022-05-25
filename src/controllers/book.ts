import { Request, Response, NextFunction } from 'express'

import Book from '../models/Book'
import Author from '../models/Author'
import BookService from '../services/book'
import isAdminEmail from '../helpers/isAdminEmail'
import {
  NotFoundError,
  BadRequestError,
  InternalServerError,
} from '../helpers/apiError'

// POST /a book
export const createBook = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const authorById = await Author.findById(req.body.author)
    let authorId = ''
    if (authorById) {
      authorId = authorById._id
    }
    const {
      category,
      title,
      description,
      isbn,
      publisher,
      publishedYear,
      total,
    } = req.body

    const book = new Book({
      author: authorId,
      category,
      title,
      description,
      isbn,
      publisher,
      publishedYear,
      total,
      isAvailable: total < 1 ? false : true,
    })
    if (isAdminEmail(req)) {
      await BookService.create(book)
      res.json(book)
    } else {
      res.json({ message: 'Not allowed to add books' })
    }
  } catch (error) {
    if (error.name === 'ValidationError') {
      next(new BadRequestError('Invalid Request', error))
    } else {
      next(new InternalServerError('Internal Server Error', error))
    }
  }
}

// GET /all/books
export const findAll = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    res.json(await BookService.findAll())
  } catch (error) {
    next(new NotFoundError('Movies not found', error))
  }
}

// GET /book/:bookId
export const findById = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    res.json(await BookService.findById(req.params.bookId))
  } catch (error) {
    next(new NotFoundError('Book not found', error))
  }
}

// PUT /book/:bookId
export const updateBook = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const update = req.body
    const bookId = req.params.bookId
    if (bookId) {
      if (isAdminEmail(req)) {
        const updatedBook = await BookService.update(bookId, update)
        res.json(updatedBook)
      } else {
        res.json({ message: 'Not allowed to update book' })
      }
    }
  } catch (error) {
    console.log(error)
    next(new NotFoundError('Book not found', error))
  }
}

// DELETE /book/:bookId
export const deleteBook = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    if (isAdminEmail(req)) {
      await BookService.deleteBook(req.params.bookId)
      res.status(204).end()
    } else {
      res.json({ message: 'Not allowed to delete book' })
    }
  } catch (error) {
    next(new NotFoundError('Book not found', error))
  }
}
