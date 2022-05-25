import mongoose, { Document } from 'mongoose'

export type LoanDocument = Document & {
  book: string[];
  user: string[];
  isReturned: boolean;
  loanedDate: Date;
}
const loanSchema = new mongoose.Schema({
  book: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Book',
    },
  ],
  user: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
  ],
  loanedDate: {
    type: Date,
  },
  isReturned: {
    type: Boolean,
    default: true,
  },
})
loanSchema.index({ loanedDate: 1 })
loanSchema.set('toJSON', {
  transform: (document, returnedObject) => {
    returnedObject.id = returnedObject._id.toString()
    delete returnedObject._id
    delete returnedObject.__v
  },
})
export default mongoose.model<LoanDocument>('Loan', loanSchema)
