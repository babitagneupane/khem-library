import Loan, { LoanDocument } from '../models/Loan'

function loan(loan: LoanDocument): Promise<LoanDocument> {
  return loan.save()
}

function findAll(): Promise<LoanDocument[]> {
  return Loan.find()
    .populate('book', { author: false, total: false, rating: false })
    .populate('user')
    .exec() // Return a Promise
}

//Find loaned book by loanId
function findById(loanId: string): Promise<LoanDocument> {
  return Loan.findById(loanId)
    .exec()
    .then((loan) => {
      if (!loan) {
        throw new Error(`Loan ${loanId} not found`)
      }
      return loan
    })
}

// update loaned book by loanId
function update(
  loanId: string,
  update: Partial<LoanDocument>
): Promise<LoanDocument> {
  return Loan.findById(loanId)
    .exec()
    .then((loan) => {
      if (!loan) {
        throw new Error(`Loan ${loanId} not found`)
      }
      if (update.book) {
        loan.book = update.book
      }
      if (update.user) {
        loan.user = update.user
      }
      if (update.isReturned) {
        loan.isReturned = update.isReturned
      }
      return loan.save()
    })
}

function deleteALoan(loanId: string): Promise<LoanDocument | null> {
  return Loan.findByIdAndDelete(loanId).exec()
}
export default {
  loan,
  findAll,
  findById,
  deleteALoan,
  update,
}
