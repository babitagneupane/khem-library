import sgMail from '@sendgrid/mail'
import { SENDGRID_API_KEY } from '../util/secrets'
sgMail.setApiKey(SENDGRID_API_KEY)
export const sendWelcomeMessage = (email: string, name: string) => {
  try {
    sgMail.send({
      to: email,
      from: 'khem.neupane@integrify.io',
      subject: 'Thanks for signing up for an account with us!',
      text: `Welcome, ${name}!! 
            One of our team member will contact you shortly!`,
    })
  } catch (error) {
    console.log(error)
  }
}

//Cancellation Email Set
export const cancellationMail = (email: string, username: string) => {
  try {
    sgMail.send({
      to: email,
      from: 'khem.neupane@integrify.io',
      subject: 'Sorry to farewell you',
      text: `Your presence was felt so important!, ${username}!! 
            You were so important and the heart-beat of our team, however
            one must say, Good Bye!`,
    })
  } catch (error) {
    console.log(error)
  }
}

//Forgot Password Reset Email Set
export const resetMail = (email: any, username: any, link: any) => {
  try {
    sgMail.send({
      to: email,
      from: 'khem.neupane@integrify.io',
      subject: 'Password Reset',
      html: `
            <p>Dear ${username},</p>
            <p>Please click on this link to login and reset your password:</p>
            <span><a href="${link}">Reset password</a></span>
            <p>Best regards</p> 
            `,
    })
  } catch (error) {
    console.log(error)
  }
}
//Thanks for changedPassword
export const changedPassword = (email: any, username: any) => {
  try {
    sgMail.send({
      to: email,
      from: 'khem.neupane@integrify.io',
      subject: 'Password changed',
      html: `
            <p>Dear ${username},</p>
            <p>You are receiving this email because you have just changed your password:</p>
            <span><a href="https://library-management-project.netlify.app/">Continue to the application</a></span>
            <p>Best regards</p> 
            `,
    })
  } catch (error) {
    console.log(error)
  }
}