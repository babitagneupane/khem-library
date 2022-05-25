import Book from '../../src/models/Book'
import BookService from '../../src/services/book'
import * as dbHelper from '../db-helper'

const nonExistingBookId = '5e57b77b5744fa0b461c7906'

async function createBook() {
  const book = new Book({
    category: 'Tragedy',
    title: 'Antony and Cleopatra',
    description: 'The two lovers and Their love affair, their war together, their defeat and, finally, their suicides have been told and retold for centuries.',
    isbn: 'JKTI-NOP1',
    publisher: 'Simon & Schuster',
    publishedYear: 1971,
    isAvailable: true,
    total: 10,
    author: ['5e57b77b5744fa0b461c7906']
  })
  return await BookService.create(book)
}

describe('book service', () => {
  beforeEach(async () => {
    await dbHelper.connect()
  })

  afterEach(async () => {
    await dbHelper.clearDatabase()
  })



  it('should create a book', async () => {
    const book = await createBook()
   
  })

  it('should get a book with id', async () => {
    const book = await createBook()
    const found = await BookService.findById(book._id)
    expect(found.title).toEqual(book.title)
    expect(found._id).toEqual(book._id)
  })

  it('should not get a non-existing book', async () => {
    expect.assertions(1)
    return BookService.findById(nonExistingBookId).catch(e => {
      expect(e.message).toMatch(`Book ${nonExistingBookId} not found`)
    })
  })

  it('should update an existing book', async () => {
    const book = await createBook()
    const update = {
      title: 'Antonio & Basonio',
      publisher: 'Simon & Schuster',
    }
    const updated = await BookService.update(book._id, update)
    expect(updated).toHaveProperty('_id', book._id)
    expect(updated).toHaveProperty('title', 'Antonio & Basonio')
    expect(updated).toHaveProperty('publisher', 'Simon & Schuster')
  })

  it('should not update a non-existing book', async () => {
    expect.assertions(1)
    const update = {
        title: 'Antonio & Basonio',
        publisher: 'Simon & Schuster',
      }
    return BookService.update(nonExistingBookId, update).catch(e => {
      expect(e.message).toMatch(`Book ${nonExistingBookId} not found`)
    })
  })

  it('should delete an existing book', async () => {
    expect.assertions(1)
    const book = await createBook()
    await BookService.deleteBook(book._id)
    return BookService.findById(book._id).catch(e => {
      expect(e.message).toBe(`Book ${book._id} not found`)
    })
  })
  afterAll(async () => {
    await dbHelper.closeDatabase()
  })
  
})
