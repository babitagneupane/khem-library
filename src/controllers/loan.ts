import { Request, Response, NextFunction } from 'express'

import Loan from '../models/Loan'
import Book from '../models/Book'
import User from '../models/User'
import LoanService from '../services/loan'
import { NotFoundError } from '../helpers/apiError'

// POST /a loan
export const loanBook = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const bookById = await Book.findById(req.body.book)
    const userById = await User.findById(req.body.user)
    let bookId = ''
    let userId = ''
    if (bookById && userById) {
      bookId = bookById._id
      userId = userById._id
      if (bookById.total < 1) {
        console.log('book not found')
        res.status(404).json({ error: 'Book not found!' })
      } else {
        const loan = new Loan({
          book: bookId,
          user: userId,
          loanedDate: new Date(),
          isReturned: false,
        })
        bookById.total -= 1
        if(bookById.total < 0){
          bookById.total = 0
        }
        bookById.isAvailable = bookById.total < 1 ? false : true
        bookById.save()
        const savedLoan = await LoanService.loan(loan)
        const savedLoanId = savedLoan._id
        userById.loan = savedLoanId
        userById.save()
        res.json(loan)
      }
      
    }
  } catch (error) {
    console.log(error)
    next(new NotFoundError('Loan not found', error))
  }
}

// GET /loan/:loanId
export const findById = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    res.json(await LoanService.findById(req.params.loanId))
  } catch (error) {
    next(new NotFoundError('Loan not found', error))
  }
}

// GET /all/loans
export const findAll = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    res.json(await LoanService.findAll())
  } catch (error) {
    next(new NotFoundError('Loans not found', error))
  }
}

// DELETE /loans/:loanId
export const deleteALoan = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const loanId = req.params.loanId
    await LoanService.deleteALoan(loanId)
    res.status(204).json({ message: 'Successfully, deleted!' })
  } catch (error) {
    next(new NotFoundError('Loan not found', error))
  }
}

// PUT /loan/:loanId
export const updateLoan = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const update = req.body
    const loanId = req.params.loanId
    const updatedLoan = await LoanService.update(loanId, update)
    res.json(updatedLoan)
  } catch (error) {
    next(new NotFoundError('Loan not found', error))
  }
}
