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
  origin: [
    'https://ph-assignment-12-c3db9.web.app',
    'https://ph-assignment-12-c3db9.firebaseapp.com',
    'http://localhost:5173',
    'http://localhost:5174',
  ],
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
  const applicationsCollection = db.collection('applications')
  const packagesCollection = db.collection('packages')
  const bookingsCollection = db.collection('bookings')

  try {
    // Role Verification Middleware
    const verifyRole = (role) => async (req, res, next) => {
      const email = req?.user?.email
      const user = await usersCollection.findOne({ email })
      if (!user || user?.role !== role) return res.status(403).send({ message: `${role} access only` })
      next()
    }

    // await client.connect();

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

    // get users for admin table
    app.get('/users', verifyToken, verifyRole('admin'), async (req, res) => {
      try {
        const { search = '', role, page = 1, limit = 10 } = req.query;
        const pageNum = parseInt(page);
        const limitNum = parseInt(limit);
        const skip = (pageNum - 1) * limitNum;

        const filter = {};

        if (search) {
          filter.$or = [
            { name: { $regex: search, $options: 'i' } },
            { email: { $regex: search, $options: 'i' } },
          ];
        }

        if (role && ['tourist', 'tourGuide', 'admin'].includes(role)) {
          filter.role = role;
        }

        const total = await usersCollection.countDocuments(filter);

        const users = await usersCollection
          .find(filter)
          .sort({ last_loggedIn: -1 })
          .skip(skip)
          .limit(limitNum)
          .toArray();

        res.send({ data: users, total });
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: 'Failed to fetch users' });
      }
    });

    // change user's role
    app.patch('/users/role', verifyToken, verifyRole('admin'), async (req, res) => {
      try {
        const { email, role } = req.body;

        if (!role) {
          return res.status(400).send({ message: 'No role given' });
        }

        const result = await usersCollection.updateOne(
          { email },
          { $set: { role } }
        );

        res.send({ modified: result.modifiedCount });
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: 'Failed to update user role' });
      }
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

    // get all story
    app.get('/all-stories', async (req, res) => {
      const result = await storiesCollection.find.toArray()
      res.send(result)
    })

    // get all stories by email
    app.get('/stories', verifyToken, async (req, res) => {
      try {
        const { email } = req.query;

        if (!email || email !== req.user.email) {
          return res.status(403).send({ message: 'Forbidden' });
        }

        const stories = await storiesCollection.aggregate([
          {
            $match: { author_email: email }
          },
          {
            $addFields: {
              sortTime: {
                $ifNull: ['$modified_at', '$createdAt']
              }
            }
          },
          {
            $sort: { sortTime: -1 }
          }
        ]).toArray();

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

    // get guide-application by email
    app.get('/applications/:email', verifyToken, async (req, res) => {
      try {
        const email = req.params.email;

        if (email !== req.user.email) {
          return res.status(403).send({ message: 'Forbidden' });
        }

        const application = await applicationsCollection.findOne({ applicant_email: email });
        if (!application) return res.status(404).send(null);

        res.send(application);
      } catch (err) {
        res.status(500).send({ message: 'Failed to fetch application' });
      }
    });

    // post or, update guide-application by email
    app.post('/applications', verifyToken, async (req, res) => {
      try {
        const { applicant_email } = req.body;

        const existingApp = await applicationsCollection.findOne({ applicant_email });

        if (existingApp && existingApp.status !== 'rejected') {
          return res.status(409).send({ message: 'Application already submitted' });
        }

        if (existingApp && existingApp.status === 'rejected') {
          const result = await applicationsCollection.updateOne(
            { _id: existingApp._id },
            {
              $set: {
                ...req.body,
                status: 'pending',
                applied_at: new Date().toISOString(),
              },
            }
          );
          return res.send({ updated: result.modifiedCount > 0 });
        }

        const result = await applicationsCollection.insertOne({
          ...req.body,
          status: 'pending',
          applied_at: new Date().toISOString(),
        });

        res.send({ insertedId: result.insertedId });
      } catch (err) {
        res.status(500).send({ message: 'Failed to submit application' });
      }
    });

    // get applications (for admin)
    app.get('/applications', verifyToken, verifyRole('admin'), async (req, res) => {
      try {
        const { search = '', status = 'pending', page = 1, limit = 10 } = req.query;
        const pageNum = parseInt(page);
        const limitNum = parseInt(limit);
        const skip = (pageNum - 1) * limitNum;

        const filter = { status };
        if (search) {
          filter.$or = [
            { applicant_name: { $regex: search, $options: 'i' } },
            { applicant_email: { $regex: search, $options: 'i' } },
          ];
        }

        const total = await applicationsCollection.countDocuments(filter);
        const applications = await applicationsCollection
          .find(filter)
          .sort({ applied_at: -1 })
          .skip(skip)
          .limit(limitNum)
          .toArray();

        res.send({ data: applications, total });
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: 'Failed to fetch applications' });
      }
    });

    // delete application by ID
    app.delete('/applications/:id', verifyToken, verifyRole('admin'), async (req, res) => {
      try {
        const { id } = req.params;
        const result = await applicationsCollection.deleteOne({ _id: new ObjectId(id) });

        res.send({ deleted: result.deletedCount > 0 });
      } catch (err) {
        res.status(500).send({ message: 'Failed to delete application' });
      }
    });

    // change application status (with role change) (accept / reject)
    app.patch('/applications/:id', verifyToken, verifyRole('admin'), async (req, res) => {
      try {
        const { id } = req.params;
        const { status } = req.body;

        const applicationId = new ObjectId(id);

        const updateResult = await applicationsCollection.updateOne(
          { _id: applicationId },
          { $set: { status } }
        );

        if (status === 'accepted') {
          const application = await applicationsCollection.findOne({ _id: applicationId });

          if (application?.applicant_email) {
            await usersCollection.updateOne(
              { email: application.applicant_email },
              { $set: { role: 'tourGuide' } }
            );
          }
        }

        res.send({ modified: updateResult.modifiedCount });
      } catch (err) {
        res.status(500).send({ message: 'Failed to update application' });
      }
    });

    // add package
    app.post('/packages', verifyToken, async (req, res) => {
      try {
        const packageData = req.body;
        const result = await packagesCollection.insertOne(packageData);
        res.send(result);
      } catch (err) {
        res.status(500).send({ message: 'Failed to add package' });
      }
    });

    // get all packages
    app.get('/packages', async (req, res) => {
      const result = await packagesCollection.find().toArray()
      res.send(result);
    })

    // get Package by ID
    app.get('/packages/:id', async (req, res) => {
      try {
        const id = req.params.id
        const result = await packagesCollection.findOne({ _id: new ObjectId(id) })
        res.send(result)
      } catch {
        res.status(500).send({ message: 'Failed to get package' })
      }
    })

    // get all guides (tourGuide)
    app.get('/guides', async (req, res) => {
      try {
        const result = await usersCollection.find({ role: 'tourGuide' }).project({ name: 1, email: 1, image: 1 }).toArray()
        res.send(result)
      } catch {
        res.status(500).send({ message: 'Failed to get guides' })
      }
    })

    // get guide by email
    app.get('/guides/:email', async (req, res) => {
      try {
        const guide = await usersCollection.findOne({ email: req.params.email, role: 'tourGuide' })
        if (!guide) return res.status(404).send({ message: 'Guide not found' })
        res.send(guide)
      } catch {
        res.status(500).send({ message: 'Failed to fetch guide' })
      }
    })

    // book a trip
    app.post('/bookings', verifyToken, async (req, res) => {
      try {
        const booking = req.body
        booking.status = 'pending'
        booking.createdAt = new Date().toISOString()
        const result = await bookingsCollection.insertOne(booking)
        res.send(result)
      } catch {
        res.status(500).send({ message: 'Failed to book tour' })
      }
    })

    // get user bookings with Pagination
    app.get('/bookings', verifyToken, async (req, res) => {
      try {
        const { email, page = 1, limit = 10 } = req.query;
        if (req.user.email !== email) return res.status(403).send({ error: 'Forbidden' });

        const query = { touristEmail: email };
        const skip = (page - 1) * limit;

        const [data, total] = await Promise.all([
          bookingsCollection.find(query).skip(parseInt(skip)).limit(parseInt(limit)).toArray(),
          bookingsCollection.countDocuments(query),
        ]);

        res.send({ data, total });
      } catch (error) {
        res.status(500).send({ error: error.message });
      }
    });

    // get a booking by ID
    app.get('/bookings/:id', verifyToken, verifyRole('tourist'), async (req, res) => {
      try {
        const id = req.params.id;
        const booking = await bookingsCollection.findOne({ _id: new ObjectId(id) });

        if (!booking) return res.status(404).send({ error: 'Booking not found' });
        if (booking.touristEmail !== req.user.email) return res.status(403).send({ error: 'Forbidden' });

        const result = await bookingsCollection.findOne({ _id: new ObjectId(id) });
        res.send(result)
      } catch {
        res.status(500).send({ message: 'Failed to get the booked tour' })
      }
    })

    // cancel booking (when status pending)
    app.delete('/bookings/:id', verifyToken, async (req, res) => {
      try {
        const id = req.params.id;
        const booking = await bookingsCollection.findOne({ _id: new ObjectId(id) });

        if (!booking) return res.status(404).send({ error: 'Booking not found' });
        if (booking.touristEmail !== req.user.email) return res.status(403).send({ error: 'Forbidden' });
        if (booking.status !== 'pending') return res.status(400).send({ error: 'Only pending bookings can be canceled' });

        const result = await bookingsCollection.deleteOne({ _id: new ObjectId(id) });
        res.send({ deletedCount: result.deletedCount });
      } catch (error) {
        res.status(500).send({ error: error.message });
      }
    });

    // Stripe Payment Intent
    app.post('/create-payment-intent', verifyToken, async (req, res) => {
      try {
        const { bookId } = req.body;
        if (!bookId) return res.status(400).send({ error: 'Booking ID is required' });

        const query = { _id: new ObjectId(bookId) };
        const bookedTrip = await bookingsCollection.findOne(query)
        if (!bookedTrip) return res.status(404).send({ error: 'Booked Trip is not found' });

        const amount = Math.round(bookedTrip.price * 100);

        const paymentIntent = await stripe.paymentIntents.create({
          amount,
          currency: 'usd',
          payment_method_types: ['card'],
        });

        res.send({ clientSecret: paymentIntent.client_secret });
      } catch (error) {
        res.status(500).send({ error: error.message });
      }
    });

    // confirm payment & update booking status
    app.post('/payments', verifyToken, async (req, res) => {
      try {
        const { bookingId, transactionId, email } = req.body;
        if (!bookingId) return res.status(400).send({ error: 'Booking ID is required' });

        const query = { _id: new ObjectId(bookingId) };
        const bookedTrip = await bookingsCollection.findOne(query)
        if (!bookedTrip) return res.status(404).send({ error: 'Booked Trip is not found' });

        if (req.user.email !== email) return res.status(403).send({ error: 'Forbidden' });

        const paymentData = {
          transactionId,
          price: bookedTrip.price,
          paidAt: new Date().toISOString(),
        };

        const updateResult = await bookingsCollection.updateOne(
          { _id: new ObjectId(bookingId) },
          {
            $set: {
              status: 'in-review',
              payment: paymentData,
            }
          }
        );

        if (updateResult.modifiedCount === 0) {
          return res.status(404).send({ error: 'Booking not found or already updated' });
        }

        res.send({ message: 'Payment recorded and booking status updated successfully' });
      } catch (error) {
        res.status(500).send({ error: error.message });
      }
    });

    // get assigned-tours (for guide)
    app.get('/assigned-tours', verifyToken, verifyRole('tourGuide'), async (req, res) => {
      const { email, page = 1, limit = 10 } = req.query;
      if (req.user.email !== email) return res.status(403).send({ error: 'Forbidden' });

      const skip = (parseInt(page) - 1) * parseInt(limit);
      const query = { guideEmail: email };
      const [data, total] = await Promise.all([
        bookingsCollection.find(query).skip(skip).limit(parseInt(limit)).toArray(),
        bookingsCollection.countDocuments(query)
      ]);
      res.send({ data, total });
    });

    // update assigned-tour's status by ID
    app.patch('/assigned-tours/:id', verifyToken, verifyRole('tourGuide'), async (req, res) => {
      const { status } = req.body;
      const id = req.params.id;
      const valid = ['accepted', 'rejected'];
      if (!valid.includes(status)) return res.status(400).send({ error: 'Invalid status' });

      const booking = await bookingsCollection.findOne({ _id: new ObjectId(id) });
      if (!booking || booking.guideEmail !== req.user.email) return res.status(404).send({ error: 'Not found' });
      if (booking.status !== 'in-review') return res.status(400).send({ error: 'Only in-review can be updated' });

      const result = await bookingsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { status } }
      );
      res.send({ modifiedCount: result.modifiedCount });
    });

    // Admin Dashboard Stats 
    app.get('/admin/stats', verifyToken, verifyRole('admin'), async (req, res) => {
      try {

        const paymentAggregation = await bookingsCollection.aggregate([
          { $match: { status: 'accepted' } },
          { $group: { _id: null, total: { $sum: '$payment.price' } } }
        ]).toArray();

        const totalPayment = paymentAggregation[0]?.total || 0;

        const [totalTourGuides, totalClients] = await Promise.all([
          usersCollection.countDocuments({ role: 'tourGuide' }),
          usersCollection.countDocuments({ role: 'tourist' }),
        ]);

        const [totalPackages, totalStories] = await Promise.all([
          packagesCollection.countDocuments(),
          storiesCollection.countDocuments(),
        ]);

        res.send({
          totalPayment,
          totalTourGuides,
          totalPackages,
          totalClients,
          totalStories,
        });
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: 'Failed to load admin stats' });
      }
    });

    // Get guide info
    app.get('/guides/:email', async (req, res) => {
      try {
        const { email } = req.params;
        const guide = await usersCollection.findOne({ email, role: 'tourGuide' });
        if (!guide) return res.status(404).send({ message: 'Guide not found' });
        res.send(guide);
      } catch (err) {
        res.status(500).send({ message: 'Failed to fetch guide' });
      }
    });

    // Get public stories by guide email
    app.get('/public-stories/:email', async (req, res) => {
      try {
        const { email } = req.params;
        const stories = await storiesCollection.find({ author_email: email }).sort({ createdAt: -1 }).toArray();
        res.send(stories);
      } catch (err) {
        res.status(500).send({ message: 'Failed to fetch stories' });
      }
    });

    // get random packages
    app.get('/packages/random/:count', async (req, res) => {
      const count = parseInt(req.params.count)
      const result = await packagesCollection.aggregate([{ $sample: { size: count } }]).toArray()
      res.send(result)
    })

    // get random guides 'tourGuide'
    app.get('/users/random/:count', async (req, res) => {
      try {
        const count = parseInt(req.params.count);

        const result = await usersCollection.aggregate([
          { $match: { role: { $regex: '^tourGuide$', $options: 'i' } } },
          { $sample: { size: count } }
        ]).toArray();

        res.send(result);
      } catch (error) {
        console.error('Error fetching random tour guides:', error);
        res.status(500).send({ error: 'Internal server error' });
      }
    });











    // Send a ping to confirm a successful connection
    // await client.db('admin').command({ ping: 1 })
    console.log('Pinged your deployment (GIRO) --> MongoDB!')
  } finally {
    // 
  }
}
run().catch(console.dir)

app.get('/', (req, res) => { res.send('Hello from GIRO Server..') })
app.listen(port, () => { console.log(`GIRO is running on port ${port}`) })
