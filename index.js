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

    // POST /jwt (get token)
    app.post('/jwt', async (req, res) => {
      const { email } = req.body;
      const token = jwt.sign({ email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '365d' });
      res.send({ token });
    });

    // save or update a users info in db
    app.post('/user', async (req, res) => {
      const userData = req.body
      userData.role = 'tourist'
      userData.created_at = new Date().toISOString()
      userData.last_loggedIn = new Date().toISOString()

      const query = { email: userData?.email }

      const alreadyExists = await usersCollection.findOne(query)
      console.log('User already exists-->', !!alreadyExists)
      if (!!alreadyExists) {
        console.log('Updating user data......')
        const result = await usersCollection.updateOne(query, {
          $set: { last_loggedIn: new Date().toISOString() },
        })
        return res.send(result)
      }

      console.log('Creating user data......')
      // return console.log(userData)
      const result = await usersCollection.insertOne(userData)
      res.send(result)
    })

    // get a user's role
    app.get('/user/role/:email', async (req, res) => {
      const email = req.params.email
      const user = await usersCollection.findOne({ email })
      if (!user) return res.status(404).send({ message: 'User Not Found.' })
      res.send({ role: user?.role })
    })

    // get user by email
    app.get('/users/:email', verifyToken, async (req, res) => {
      try {
        const { email } = req.params;
        const user = await usersCollection.findOne({ email });

        if (!user) return res.status(404).json({ message: 'User not found' });

        res.json(user);
      } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({ message: 'Internal server error' });
      }
    });

    




















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
