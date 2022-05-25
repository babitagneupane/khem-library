import mongoose, { Document } from 'mongoose'
import { LoanDocument } from './Loan'

export type UserDocument = Document & {
  username: string;
  password: string;
  isAdmin: boolean;
  email: string;
  image?: string;
  googleId?: number;
  joinedDate: Date;
  loan: string;
}
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    minlength: 4,
    maxlength: 20,
  },
  password: {
    type: String,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  loan: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Loan',
    },
  ],
  joinedDate: { type: Date },
  googleId: { type: Number, required: false },
  isAdmin: { type: Boolean, default: false },
  image: { type: String },
})
userSchema.index({ email: 1, unique: true })
userSchema.set('toJSON', {
  transform: (document, returnedObject) => {
    returnedObject.id = returnedObject._id.toString()
    delete returnedObject._id
    delete returnedObject.__v
  },
})
export default mongoose.model<UserDocument>('User', userSchema)
