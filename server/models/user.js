const pool = require('../config/database')
const bcrypt = require('bcrypt')
const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const secretKey = crypto.randomBytes(64).toString('hex')

const user = {
    id: Number,
    name: String,
    email: String,
    password: String
}
  
// Define functions to interact with the model data
const userModel = {
    getAll: async () => {
        const { rows } = await pool.query('SELECT * FROM users')
        return rows
    },
    getById: async (id) => {
        const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [id])
        return rows[0]
    },
    getByEmail: async(email, password) => {
        const { rows } = await pool.query('SELECT * FROM users WHERE emailaddress = $1', [email])
        const user = rows[0]

        if (user) {
            const isPasswordValid = await bcrypt.compare(password, user.password)

            if (isPasswordValid) {
                return user
            }
        }

        return null
    },
    create: async (user) => {
        const salt = await bcrypt.genSalt(10)
        const hashedPassword = await bcrypt.hash(user.password, salt)

        const query = 'INSERT INTO users (firstname, lastname, emailaddress, password) VALUES ($1, $2, $3, $4) RETURNING *;'
        const { rows } = await pool.query(query, [user.firstname, user.lastname, user.emailaddress, hashedPassword])
        return rows[0]
    },
    generateAuthToken: (user) => {
        const payload = {
            id: user.id,
            firstname: user.firstname,
            lastname: user.lastname,
            emailaddress: user.emailaddress
        }

        const token = jwt.sign(payload, secretKey, { expiresIn: '1h' })
        return token
    },
    verifyAuthToken: (token) => {
        try {
            const decoded = jwt.verify(token, secretKey)
            return decoded
        } catch (err) {
            return null
        }
    }
}
  
module.exports = userModel