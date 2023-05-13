import { request } from '../utilities/api'

const usersURL = '/auth/users'

const getAllUsers = () => request('GET', usersURL)
const getUser = (id) => request('GET', `${usersURL}/${id}`)
const createUser = (user) => request('POST', usersURL, user)
const loginUser = (credentials) => request('POST', `${usersURL}/login`, credentials)

export default {
    getAllUsers,
    getUser,
    createUser,
    loginUser
}