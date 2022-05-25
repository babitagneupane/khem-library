import express from 'express'
import compression from 'compression'
import session from 'express-session'
import bodyParser from 'body-parser'
import lusca from 'lusca'
import mongo from 'connect-mongo'
import flash from 'express-flash'
import path from 'path'
import mongoose from 'mongoose'
import passport from 'passport'
import './config/passport'
import bluebird from 'bluebird'
import cors from 'cors'
import { MONGODB_URI, SESSION_SECRET } from './util/secrets'
import bookRouter from './routers/book'
import authorRouter from './routers/author'
import userRouter from './routers/user'
import forgetRouter from './routers/forgetRoute'
import changeRouter from './routers/changeRoute'
import loginRouter from './routers/login'
import loanRouter from './routers/loan'
import authenticate from './routers/auth'

import apiErrorHandler from './middlewares/apiErrorHandler'
//import apiContentType from './middlewares/apiContentType'

const app = express()
const mongoUrl = MONGODB_URI

mongoose.Promise = bluebird
mongoose
  .connect(mongoUrl, {
    useNewUrlParser: true,
    useCreateIndex: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    /** ready to use. The `mongoose.connect()` promise resolves to undefined. */
  })
  .catch((err: Error) => {
    console.log(
      'MongoDB connection error. Please make sure MongoDB is running. ' + err
    )
    process.exit(1)
  })

// Express configuration
app.set('port', process.env.PORT || 3001)
app.use(
  session({
    secret: SESSION_SECRET,
    proxy: true,
    resave: true,
    saveUninitialized: true,
  })
)
// Use common 3rd-party middlewares
app.use(compression())
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))
app.use(lusca.xframe('SAMEORIGIN'))
app.use(lusca.xssProtection(true))
app.use(passport.initialize())
app.use(passport.session())
app.use(cors())

app.use('/api/v1/books', bookRouter)
app.use('/api/v1/authors', authorRouter)
app.use('/api/v1/users', userRouter)
app.use('/api/v1/loans', loanRouter)
app.use('/api/v1/login', loginRouter)
app.use('/api/v1/forgetpass', forgetRouter)
app.use('/api/v1/changepass', changeRouter)
app.use('/api/v1/auth', authenticate)

// Custom API error handler
app.use(apiErrorHandler)

export default app
