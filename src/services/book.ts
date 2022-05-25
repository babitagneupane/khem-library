import Book, { BookDocument } from '../models/Book'

function create(book: BookDocument): Promise<BookDocument> {
  return book.save()
}
function findAll(): Promise<BookDocument[]> {
  return Book.find().populate('author', { book: false }).exec() // Return a Promise
}
function findById(bookId: string): Promise<BookDocument> {
  return Book.findById(bookId)
    .exec()
    .then((book) => {
      if (!book) {
        throw new Error(`Book ${bookId} not found`)
      }
      return book
    })
}

function update(
  bookId: string,
  update: Partial<BookDocument>
): Promise<BookDocument> {
  return Book.findById(bookId)
    .exec()
    .then((book) => {
      if (!book) {
        throw new Error(`Book ${bookId} not found`)
      }
      if (update.category) {
        book.category = update.category
      }
      if (update.title) {
        book.title = update.title
      }
      if (update.description) {
        book.description = update.description
      }
      if (update.isbn) {
        book.isbn = update.isbn
      }
      if (update.publisher) {
        book.publisher = update.publisher
      }
      if (update.publishedYear) {
        book.publishedYear = update.publishedYear
      }
      if (update.total) {
        book.total = update.total
        book.isAvailable = book.total < 1 ? false : true
      }
      if (update.author) {
        book.author = update.author
      }
      if (update.rating) {
        book.rating = update.rating
      }
      return book.save()
    })
}

function deleteBook(bookId: string): Promise<BookDocument | null> {
  return Book.findByIdAndDelete(bookId).exec()
}
export default {
  create,
  findAll,
  findById,
  update,
  deleteBook,
}
