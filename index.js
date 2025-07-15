require('dotenv').config()
const express = require('express')
const cors = require('cors')
const { MongoClient, ServerApiVersion } = require('mongodb')
const jwt = require('jsonwebtoken')
const { ObjectId } = require('mongodb');
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
  const storiesCollection = db.collection('stories')

  try {
    await client.connect();

    // POST /jwt (get token)
    app.post('/jwt', async (req, res) => {
      const { email } = req.body;
      const token = jwt.sign({ email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '365d' });
      res.send({ token });
    });

    // save or update a user's info in db
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

    // update user by email
    app.patch('/users/:email', verifyToken, async (req, res) => {
      const { email } = req.params;

      if (email !== req.user.email) {
        return res.status(403).send({ message: 'Forbidden' });
      }

      const { name, image } = req.body;
      const result = await usersCollection.updateOne(
        { email },
        { $set: { name, image } }
      );
      res.send(result);
    });

    // add Story
    app.post('/stories', verifyToken, async (req, res) => {
      try {
        const storyData = req.body;
        const result = await storiesCollection.insertOne(storyData);
        res.send(result);
      } catch (err) {
        res.status(500).send({ message: 'Failed to create story' });
      }
    });

    // get all stories by email
    app.get('/stories', verifyToken, async (req, res) => {
      try {
        const { email } = req.query;

        if (!email || email !== req.user.email) {
          return res.status(403).send({ message: 'Forbidden' });
        }

        const stories = await storiesCollection
          .find({ author_email: email })
          .sort({ createdAt: -1 })
          .toArray();

        res.send(stories);
      } catch (err) {
        res.status(500).send({ message: 'Failed to fetch user stories' });
      }
    });

    // get story by ID
    app.get('/stories/:id', verifyToken, async (req, res) => {
      try {
        const { id } = req.params;

        const story = await storiesCollection.findOne({ _id: new ObjectId(id) });

        if (!story || story.author_email !== req.user.email) {
          return res.status(403).send({ message: 'Forbidden' });
        }

        const result = await storiesCollection.findOne({ _id: new ObjectId(id) });
        res.send(result);
      } catch {
        res.status(500).send({ message: 'Failed to find story' });
      }
    })

    // edit story by ID
    app.patch('/stories/:id', verifyToken, async (req, res) => {
      try {
        const { id } = req.params;
        const email = req.query.email;

        if (!email || email !== req.user.email) {
          return res.status(403).send({ message: 'Forbidden' });
        }

        const { $set, $push, $pull } = req.body;

        const filter = { _id: new ObjectId(id), author_email: email };
        const updateDoc = {
          ...(!!$set && { $set: { ...$set, modified_at: new Date().toISOString() } }),
          ...(!!$push && { $push }),
          ...(!!$pull && { $pull }),
        };

        const result = await storiesCollection.updateOne(filter, updateDoc);
        res.send(result);
      } catch (err) {
        res.status(500).send({ message: 'Failed to update story' });
      }
    });

    // delete story by ID
    app.delete('/stories/:id', verifyToken, async (req, res) => {
      try {
        const { id } = req.params;

        const story = await storiesCollection.findOne({ _id: new ObjectId(id) });

        if (!story || story.author_email !== req.user.email) {
          return res.status(403).send({ message: 'Forbidden' });
        }

        const result = await storiesCollection.deleteOne({ _id: new ObjectId(id) });
        res.send(result);
      } catch (err) {
        res.status(500).send({ message: 'Failed to delete story' });
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
