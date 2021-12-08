const express = require('express')
const path = require('path')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const User = require('./model/user')
const bcryptjs = require('bcryptjs')
const jwt = require("jsonwebtoken")

const JWT_SECRET = 'lsdjflsdk@lksgldkgsllglx.gddx'

mongoose.connect('mongodb://localhost:27017/login-app-db')
const app = express();
app.use('/', express.static(path.join(__dirname, 'static')))
app.use(bodyParser.json())

app.post('/api/login', async (req, res) => {
    const {login, password} = req.body
    const user = await User.findOne({username: login}).lean()

    if(!user)
        return res.json({ status: 'error', error: 'Invalid username' })

    if(await bcryptjs.compare(password, user.password,)) {

        const token = jwt.sign({
            id: user._id,
            username: user.username
        }, JWT_SECRET)

        return res.json({ status: 'ok', data: token})
    }

    res.json({status: 'error', data : 'Invalid password'})
} )

app.post('/api/register', async(req, res) => {
    const {username, password: plainTextPassword} = req.body

    if(!username || typeof username !== 'string' || !plainTextPassword || typeof plainTextPassword !== 'string')
        return res.json({ status: 'error', error: 'Invalid username/password' })

    if(plainTextPassword.length < 5)
        return res.json({
            status: 'error',
            error: 'Password to small. Should be at least 6 characters'
        })

    const password = await bcryptjs.hash(plainTextPassword, 10)

    try {
        const response = await User.create({
            username,
            password
        })
        console.log('User created: ',response)
    } catch (err) {
        if(err.code === 11000) {
            //duplicate kay
            return res.json({status: 'error', error: 'Username already in use'})
        }
        throw err
    }

    res.json({status: 'ok'})
})

app.post('/api/change-password', async(req, res) => {
    const {token, newPassword} = req.body

    if (!newPassword || typeof newPassword !== 'string') {
        return res.json({ status: 'error', error: 'Invalid password' })
    }

    if(newPassword.length < 5)
        return res.json({
            status: 'error',
            error: 'Password to small. Should be at least 6 characters'
        })

    try{
        const user = jwt.verify(token, JWT_SECRET)

        const _id = user.id

        const hashedPassword = await bcryptjs.hash(newPassword, 10)

        await User.updateOne({_id}, {
            $set: {password: hashedPassword}
        })
        res.json({status: 'ok'})
    } catch (e) {
        res.json({status: 'error', error: ':)'})
    }
})

app.listen(5000, () => {
    console.log("Server up at 5000 ")
})
