import mongoose, { Document } from 'mongoose'

export type BookDocument = Document & {
  category: string;
  title: string;
  description: string;
  isbn: string;
  publisher: string;
  publishedYear: Date;
  isAvailable: boolean;
  total: number;
  rating: number;
  author: string[];
}
const bookSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
  },
  category: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    maxlength: 350,
    minlength: 10,
    required: true,
  },
  isbn: {
    type: String,
    required: true,
  },
  publisher: {
    type: String,
    required: true,
  },
  publishedYear: {
    type: Date,
    required: true,
  },
  isAvailable: {
    type: Boolean,
  },
  total: {
    type: Number,
    default: 0,
  },
  rating: {
    type: Number,
    default: 0,
  },
  author: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Author',
    },
  ],
})
bookSchema.index({ isbn: 1, unique: true })
bookSchema.set('toJSON', {
  transform: (document, returnedObject) => {
    returnedObject.id = returnedObject._id.toString()
    delete returnedObject._id
    delete returnedObject.__v
  },
})
export default mongoose.model<BookDocument>('Book', bookSchema)
