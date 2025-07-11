require('dotenv').config()
const express = require('express')
const cors = require('cors')
const { MongoClient, ServerApiVersion } = require('mongodb')
const jwt = require('jsonwebtoken')
const stripe = require('stripe')(process.env.STRIPE_SK_KEY)

const app = express()
const port = process.env.PORT || 3000

// Middleware
const corsOptions = {
  origin: ['http://localhost:5173'],
  credentials: true,
}
app.use(cors(corsOptions))
app.use(express.json())

// JWT Middleware
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1]
  if (!token) return res.status(401).send({ message: 'Unauthorized' })

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) return res.status(401).send({ message: 'Invalid Token' })
    req.user = decoded
    next()
  })
}

// MongoDB Setup
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
})
async function run() {
  const db = client.db('tripdb')
  const usersCollection = db.collection('users')

  try {
    await client.connect();



    // Send a ping to confirm a successful connection
    await client.db('admin').command({ ping: 1 })
    console.log('Pinged your deployment (GIRO) --> MongoDB!')
  } finally {
    // 
  }
}
run().catch(console.dir)

app.get('/', (req, res) => { res.send('Hello from GIRO Server..') })
app.listen(port, () => { console.log(`GIRO is running on port ${port}`) })
