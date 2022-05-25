import request from 'supertest'

import  { BookDocument } from '../../src/models/Book'
import app from '../../src/app'
import * as dbHelper from '../db-helper'
const nonExistingBookId = '5e57b77b5744fa0b461c7906'
const nonExistingAuthorId = '5e57b77b5744fa0b461c7907'

async function createBook(override?: Partial<BookDocument>) {
  let book = {
    category: 'Tragedy',
    title: 'Antony and Cleopatra',
    description: 'The two lovers and Their love affair, their war together, their defeat and, finally, their suicides have been told and retold for centuries.',
    isbn: 'JKTI-NOP1',
    publisher: 'Simon & Schuster',
    publishedYear: 1971,
    isAvailable: true,
    total: 10,
    author: [nonExistingAuthorId]
  }

  if (override) {
    book = { ...book, ...override }
  }

  return await request(app)
    .post('/api/v1/books')
    .send(book)
}

describe('book controller', () => {
  beforeEach(async () => {
    await dbHelper.connect()
    
  })

  afterEach(async () => {
    await dbHelper.clearDatabase()
  })
  afterAll(async () => {
    await dbHelper.closeDatabase()
  })
  it('should not create a book with wrong data', async () => {
    const res = await request(app)
      .post('/api/v1/books')
      .send({
        hi: 'Man',
        How: 'are you',
      })
    expect(res.status).toBe(400)
  })

  it('should get back an existing book', async () => {
    let res = await createBook()
    //expect(res.status).toBe(200)
    const bookId = res.body.id
       res = await request(app)
      .get(`/api/v1/books/${bookId}`)

    expect(res.body.id).toEqual(bookId)
  })
  it('should not get back a non-existing book', async () => {
    const res = await request(app)
      .get(`/api/v1/books/${nonExistingBookId}`)
    expect(res.status).toBe(404)
  })

  /*
  it('should create a book', async () => {
    const res = await createBook()
    //expect(res.status).toBe(200)
    expect(res.body).toHaveProperty('_id')
    expect(res.body.title).toBe('Antony and Cleopatra')
  })

    it('should get back all books', async () => {
    const res1 = await createBook({
        category: '2Tragedy2',
        title: '2Antony and Cleopatra2',
        description: '2The two lovers and Their love affair, their war together, their defeat and, finally, their suicides have been told and retold for centuries.',
        isbn: '2JKTI-NOP1',
        publisher: '2Simon & Schuster2',
        publishedYear: 1972,
        isAvailable: true,
        total: 10,
        author: [nonExistingAuthorId]
    })
    const res2 = await createBook({
        category: 'Tragedy',
        title: 'Antony and Cleopatra',
        description: 'The two lovers and Their love affair, their war together, their defeat and, finally, their suicides have been told and retold for centuries.',
        isbn: 'JKTI-NOP1',
        publisher: 'Simon & Schuster',
        publishedYear: 1971,
        isAvailable: true,
        total: 10,
        author: [nonExistingAuthorId]
    })

    const res3 = await request(app)
      .get('/api/v1/books')

    expect(res3.body.length).toEqual(2)
    expect(res3.body[0].id).toEqual(res1.body.id)
    expect(res3.body[1].id).toEqual(res2.body.id)
  })

   it('should update an existing book', async () => {
    let res = await createBook()
    //expect(res.status).toBe(200)

    const bookId = res.body.id
    const update = {
      title: 'Updated book title',
      publishedYear: 2016
    }

    res = await request(app)
      .put(`/api/v1/books/${bookId}`)
      .send(update)

    expect(res.status).toEqual(200)
    expect(res.body.title).toEqual('Updated book title')
    expect(res.body.publishedYear).toEqual(2016)
  })

  it('should delete an existing book', async () => {
    let res = await createBook()
    //expect(res.status).toBe(200)
    const bookId = res.body.id

    res = await request(app)
      .delete(`/api/v1/books/${bookId}`)

    expect(res.status).toEqual(204)

    res = await request(app)
      .get(`/api/v1/books/${bookId}`)
    expect(res.status).toBe(404)
  })
  */
 
})

