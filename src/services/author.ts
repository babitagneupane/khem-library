import Author, { AuthorDocument } from '../models/Author'

function create(author: AuthorDocument): Promise<AuthorDocument> {
  return author.save()
}

function findAll(): Promise<AuthorDocument[]> {
  return Author.find().populate('book', { author: false }).exec() // Return a Promise
}

function findById(authorId: string): Promise<AuthorDocument> {
  return Author.findById(authorId)
    .exec()
    .then((author) => {
      if (!author) {
        throw new Error(`Author ${authorId} not found`)
      }
      return author
    })
}

function update(
  authorId: string,
  update: Partial<AuthorDocument>
): Promise<AuthorDocument> {
  return Author.findById(authorId)
    .exec()
    .then((author) => {
      if (!author) {
        throw new Error(`Author ${authorId} not found`)
      }
      if (update.firstName) {
        author.firstName = update.firstName
      }
      if (update.lastName) {
        author.lastName = update.lastName
      }
      if (update.email) {
        author.email = update.email
      }
      if (update.dob) {
        author.dob = update.dob
      }
      return author.save()
    })
}

function deleteAuthor(authorId: string): Promise<AuthorDocument | null> {
  return Author.findByIdAndDelete(authorId).exec()
}
export default {
  create,
  findAll,
  findById,
  deleteAuthor,
  update,
}
