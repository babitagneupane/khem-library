import passport from 'passport'
import PassportGoogleStrategy from 'passport-google-oauth20'

import { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET } from '../util/secrets'
import UserService from '../services/user'
import User from '../models/User'

const GoogleStrategy = PassportGoogleStrategy.Strategy

passport.serializeUser<any, any>((user, done) => done(null, user.id))
passport.deserializeUser((id, done) => {
  User.findById(id, (err, user) => done(err, user))
})
passport.use(
  new GoogleStrategy(
    {
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: '/api/v1/auth/google/callback',
    },
    (accessToken: any, refreshToken: any, profile, done: any) =>{
      let emailId = '' 
      const photoId = profile._json['picture']
      if (profile.emails) {
        emailId = profile.emails[0].value
      }
     User.findOne({ email: emailId }).then((user)=>{
      if (user) {
        done(null, user)
      } else {
        const newUser = new User({
          username: profile.name?.givenName,
          email: emailId,
          image: photoId,
          googleId: profile.id,
        })
        newUser.save().then((newUser)=>{
          done(null, newUser)
        })
        
      }
     })

    }
  )
)
export default passport