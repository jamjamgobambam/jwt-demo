const userModel = require('../models/user')

const authenticateJWT = async (req, res, next) => {
     // Extract the token from the authorization header
    const token = req.headers.authorization?.split(' ')[1]

    if (!token) {
        return res.status(401).json({ error: 'Missing authorization token' })
    }

    try {
        const decoded = userModel.verifyAuthToken(token)

        if (!decoded) {
        return res.status(401).json({ error: 'Invalid token' })
        }

        const user = await userModel.getById(decoded.id)

        if (!user) {
        return res.status(401).json({ error: 'User not found' })
        }

        // Attach the user object to the request for further use
        req.user = user
        next()
    } catch (err) {
        return res.status(500).json({ error: 'Internal server error' })
    }
}

module.exports = { authenticateJWT }