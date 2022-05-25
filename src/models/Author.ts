import mongoose, { Document } from 'mongoose'

export type AuthorDocument = Document & {
  firstName: string;
  lastName: string;
  email: string;
  dob: Date;
}
const authorSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true,
  },
  lastName: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    unique: true,
  },
  dob: {
    type: Date,
    required: true,
    min: 1700,
  },
})
authorSchema.index({ email: 1, unique: true })
authorSchema.set('toJSON', {
  transform: (document, returnedObject) => {
    returnedObject.id = returnedObject._id.toString()
    delete returnedObject._id
    delete returnedObject.__v
  },
})
export default mongoose.model<AuthorDocument>('Author', authorSchema)
