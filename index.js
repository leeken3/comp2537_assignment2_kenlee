require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const MongoStore = require('connect-mongo');
const session = require('express-session');
const { ObjectId } = require('mongodb');
const saltRounds = 12;

const app = express();
const port = process.env.PORT || 3000;
const Joi = require("joi");

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

const { database } = require('./databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}));

app.get('/', (req, res) => {
    const username = req.session.username;
    if (!username) {
        res.render('index', { username: null });
    } else {
        res.render('index', { username: username });
    }
});


app.get('/nosql-injection', async (req, res) => {
    var username = req.query.user;

    if (!username) {
        res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
        return;
    }
    console.log("user: " + username);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    //If we didn't use Joi to validate and check for a valid URL parameter below
    // we could run our userCollection.find and it would be possible to attack.
    // A URL parameter of user[$ne]=name would get executed as a MongoDB command
    // and may result in revealing information about all users or a successful
    // login without knowing the correct password.
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }

    const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, _id: 1 }).toArray();

    console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/signup', (req, res) => {
    res.render('signup');
});

app.post('/signupSubmit', async (req, res) => {
    var username = req.body.username;
    var password = req.body.password;
    var email = req.body.email;

    if (!username) {
        res.render('signup', { error: 'Name is required.' });
    } else if (!email) {
        res.render('signup', { error: 'Email is required.' });
    } else if (!password) {
        res.render('signup', { error: 'Password is required.' });
    } else {
        const schema = Joi.object({
            username: Joi.string().alphanum().max(20).required(),
            password: Joi.string().max(20).required(),
            email: Joi.string().email().max(100).required()
        });

        const validationResult = schema.validate({ username, email, password });
        if (validationResult.error != null) {
            console.log(validationResult.error);
            res.render('signup', { error: 'Invalid input. Please follow the rules.' });
            return;
        }

        var hashedPassword = await bcrypt.hash(password, saltRounds);

        await userCollection.insertOne({ username: username, email: email, password: hashedPassword, type: 'user' });
        console.log('Inserted user');

        req.session.authenticated = true;
        req.session.username = username;
        req.session.userType = 'user';

        res.redirect('/members');
    }
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/loginSubmit', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object({
        email: Joi.string().email().max(100).required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.render('login', { error: 'Invalid input. Please check your email and password.' });
        return;
    }

    const result = await userCollection
        .find({ email: email })
        .project({ username: 1, email: 1, password: 1, _id: 1, type: 1 })
        .toArray();

    console.log(result);

    if (result.length != 1) {
        console.log("user not found");
        res.render('login', { error: 'Invalid email/password combination.' });
        return;
    }

    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.username = result[0].username;
        req.session.cookie.maxAge = expireTime;
        req.session.userType = result[0].type || 'user';

        res.redirect('/members');
        return;
    } else {
        console.log("incorrect password");
        res.render('login', { error: 'Invalid email/password combination.' });
        return;
    }
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }

    var username = req.session.username;

    var images = ['sga1.jpg', 'sga2.jpg', 'sga3.jpg'];

    res.render('members', { username: username, images: images });
});

app.use(express.static(__dirname + "/public"));

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.log('Error destroying session:', err);
            res.status(500).render('error', { message: 'Error logging out.' });
        } else {
            res.render('logout');
        }
    });
});

app.get('/admin', async (req, res) => {
    // Check if the user is authenticated (Authentication code)
    const authenticated = req.session.authenticated;

    if (!authenticated) {
        return res.redirect('/login');
    }

    // Check if the user is an admin (Authorization code)
    const isAdmin = req.session.userType === 'admin';

    if (!isAdmin) {
        // Redirect or show a 403 error if they are authenticated but not an admin
        return res.status(403).render('admin', { authorized: false });
    }

    // Fetch the list of users and render the admin page if the user is an admin
    const users = await userCollection.find().toArray();
    res.render('admin', { authorized: true, username: req.session.username, users: users });
});

app.get('/promote/:id', async (req, res) => {
    if (req.session.userType !== 'admin') {
        res.status(403).render('error', { message: 'Unauthorized action.' });
        return;
    }

    // Ensure that the user exists before promoting
    const userToPromote = await userCollection.findOne({ _id: new ObjectId(req.params.id) });
    if (!userToPromote) {
        return res.status(404).render('error', { message: 'User not found.' });
    }

    await userCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { type: 'admin' } }
    );
    res.redirect('/admin');
});

app.get('/demote/:id', async (req, res) => {
    if (req.session.userType !== 'admin') {
        res.status(403).render('error', { message: 'Unauthorized action.' });
        return;
    }

    // Ensure that the user exists before demoting
    const userToDemote = await userCollection.findOne({ _id: new ObjectId(req.params.id) });
    if (!userToDemote) {
        return res.status(404).render('error', { message: 'User not found.' });
    }

    await userCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { type: 'user' } }
    );
    res.redirect('/admin');
});



app.get("*dummy", (req, res) => {
    res.status(404);
    res.render('404');
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});