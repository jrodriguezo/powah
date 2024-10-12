import DBLocal from 'db-local'
import bcrypt from 'bcrypt'
import { SALT_ROUNDS } from './config.js'
const { Schema } = new DBLocal({ path: './db' })

const User = Schema('User', {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true }
})

export class UserRepository {
  static async create ({ username, password }) {
    Validation.username(username)

    const user = User.findOne({ username })
    if (user) throw new Error('Username already exists')
    const id = crypto.randomUUID()
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS)

    User.create({
      _id: id,
      username,
      password: hashedPassword
    }).save()

    return id
  }

  static async login ({ username, password }) {
    Validation.username(username)

    const user = Validation.exist(username)

    const isValid = await bcrypt.compare(password, user.password)
    if (!isValid) throw new Error('Password is invalid')

    const { password: _, ...publicUser } = user

    return publicUser
  }
}

class Validation {
  static username (username) {
    if (typeof username !== 'string') {
      throw new Error('Username must be a string')
    }

    return true
  }

  static exist (username) {
    const user = User.findOne({ username })
    if (!user) throw new Error('Username does not exist')
    return user
  }
}
