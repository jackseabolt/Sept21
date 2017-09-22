'use strict';
const bodyParser = require('body-parser');
const express = require('express');
const mongoose = require('mongoose');
const morgan = require('morgan');
const passport = require('passport');
const { BasicStrategy } = require('passport-http');
const jwt = require('jsonwebtoken');
const {
  // Assigns the Strategy export to the name JwtStrategy using object
  // destructuring
  // https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Operators/Destructuring_assignment#Assigning_to_new_variable_names
  Strategy: JwtStrategy,
  ExtractJwt
} = require('passport-jwt');

const { DATABASE_URL, PORT, JWT_SECRET, JWT_EXPIRY } = require('./config');
const { BlogPost, User } = require('./models');


const app = express();

app.use(morgan('common'));
app.use(bodyParser.json());

mongoose.Promise = global.Promise;
const basicAuth = passport.authenticate('basic', { session: false });

const createAuthToken = user => {
  return jwt.sign({ user }, JWT_SECRET, {
    
    subject: user.username,
    expiresIn: JWT_EXPIRY,
    algorithm: 'HS256'
  });
};

const basicStrategy = new BasicStrategy((username, password, callback) => {
  let user;
  User.findOne({username: username})
    .then(_user => {
      user = _user;
      if (!user) {
        // Return a rejected promise so we break out of the chain of .thens.
        // Any errors like this will be handled in the catch block.
        return Promise.reject({
          reason: 'LoginError',
          message: 'Incorrect username or password'
        });
      }
      return user.validatePassword(password);
    })
    .then(isValid => {
      if (!isValid) {
        return Promise.reject({
          reason: 'LoginError',
          message: 'Incorrect username or password'
        });
      }
      return callback(null, user);
    })
    .catch(err => {
      if (err.reason === 'LoginError') {
        return callback(null, false, err);
      }
      return callback(err, false);
    });
});


console.log('jwtsecret logging', JWT_SECRET);
const jwtStrategy = new JwtStrategy(
  {
    secretOrKey: JWT_SECRET,
    // Look for the JWT as a Bearer auth header
    jwtFromRequest: ExtractJwt.fromAuthHeaderWithScheme('Bearer'),
    // Only allow HS256 tokens - the same as the ones we issue
    algorithms: ['HS256']
  },
  (payload, done) => {
    done(null, payload.user);
  }
);

passport.use(basicStrategy);
app.use(passport.initialize());
passport.use(jwtStrategy);

app.get('/posts', (req, res) => {
  BlogPost
    .find()
    .then(posts => {
      res.json(posts.map(post => post.apiRepr()));
    })
    .catch(err => {
      console.error(err);
      res.status(500).json({ error: 'something went terribly wrong' });
    });
});

app.post('/login', basicAuth, (req, res) => {
  const authToken = createAuthToken(req.user.apiRepr());
  res.json({authToken});
} 
);

app.get('/posts/:id', (req, res) => {
  BlogPost
    .findById(req.params.id)
    .then(post => res.json(post.apiRepr()))
    .catch(err => {
      console.error(err);
      res.status(500).json({ error: 'something went horribly awry' });
    });
});

app.post('/posts', basicAuth, (req, res) => {
  const requiredFields = ['title', 'content'];
  for (let i = 0; i < requiredFields.length; i++) {
    const field = requiredFields[i];
    if (!(field in req.body)) {
      const message = `Missing \`${field}\` in request body`;
      console.error(message);
      return res.status(400).send(message);
    }
  }

  BlogPost
    .create({
      title: req.body.title,
      content: req.body.content,
      author: {
        firstName: req.user.firstName,
        lastName: req.user.lastName
      }
    })
    .then(blogPost => res.status(201).json(blogPost.apiRepr()))
    .catch(err => {
      console.error(err);
      res.status(500).json({ error: 'Something went wrong' });
    });

});


app.delete('/posts/:id', basicAuth, (req, res) => {
  BlogPost
    .findByIdAndRemove(req.params.id)
    .then(() => {
      res.status(204).json({ message: 'success' });
    })
    .catch(err => {
      console.error(err);
      res.status(500).json({ error: 'something went terribly wrong' });
    });
});


app.put('/posts/:id', basicAuth, (req, res) => {
  if (!(req.params.id && req.body.id && req.params.id === req.body.id)) {
    res.status(400).json({
      error: 'Request path id and request body id values must match'
    });
  }

  const updated = {};
  const updateableFields = ['title', 'content', 'author'];
  updateableFields.forEach(field => {
    if (field in req.body) {
      updated[field] = req.body[field];
    }
  });

  BlogPost
    .findByIdAndUpdate(req.params.id, { $set: updated }, { new: true })
    .then(updatedPost => res.status(204).end())
    .catch(err => res.status(500).json({ message: 'Something went wrong' }));
});


app.delete('/:id', (req, res) => {
  BlogPost
    .findByIdAndRemove(req.params.id)
    .then(() => {
      console.log(`Deleted blog post with id \`${req.params.ID}\``);
      res.status(204).end();
    });
});







app.post('/users', (req, res) => {
  if (!req.body) {
    return res.restauts(400).json({ message: 'No request body' });
  }

  if (!('username' in req.body)) {
    return res.status(422).json({ message: 'Missing field: username' });
  }

  let { username, password, firstName, lastName } = req.body;

  if (typeof username !== 'string') {
    return res.status(422).json({ message: 'Incorrect field type: username' });
  }

  username = username.trim();

  if (username === '') {
    return res.status(422).json({ message: 'Incorrect field length: username' });
  }

  if (!(password)) {
    return res.status(422).json({ message: 'Missing field: password' });
  }

  if (typeof password !== 'string') {
    return res.status(422).json({ message: 'Incorrect field type: password' });
  }

  password = password.trim();

  if (password === '') {
    return res.status(422).json({ message: 'Incorrect field length: password' });
  }

  return User
    .find({ username })
    .count()
    .then(count => {
      if (count > 0) {
        return res.status(422).json({ message: 'username already taken' });
      }
      return User.hashPassword(password);
    })
    .then(hash => {
      return User
        .create({
          username: username,
          password: hash,
          firstName: firstName,
          lastName: lastName
        });
    })
    .then(user => {
      return res.status(201).json(user.apiRepr());
    })
    .catch(err => {
      res.status(500).json({ message: 'Internal server error' });
    });
});

app.use('*', function (req, res) {
  res.status(404).json({ message: 'Not Found' });
});

// closeServer needs access to a server object, but that only
// gets created when `runServer` runs, so we declare `server` here
// and then assign a value to it in run

let server;

// this function connects to our database, then starts the server
function runServer(databaseUrl = DATABASE_URL, port = PORT) {
  return new Promise((resolve, reject) => {
    mongoose.connect(databaseUrl, err => {
      if (err) {
        return reject(err);
      }
      server = app.listen(port, () => {
        console.log(`Your app is listening on port ${port}`);
        resolve();
      })
        .on('error', err => {
          mongoose.disconnect();
          reject(err);
        });
    });
  });
}

// this function closes the server, and returns a promise. we'll
// use it in our integration tests later.
function closeServer() {
  return mongoose.disconnect().then(() => {
    return new Promise((resolve, reject) => {
      console.log('Closing server');
      server.close(err => {
        if (err) {
          return reject(err);
        }
        resolve();
      });
    });
  });
}

// if server.js is called directly (aka, with `node server.js`), this block
// runs. but we also export the runServer command so other code (for instance, test code) can start the server as needed.
if (require.main === module) {
  runServer().catch(err => console.error(err));
}

module.exports = { runServer, app, closeServer };
