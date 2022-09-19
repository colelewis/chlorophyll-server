const express = require('express');
const cookieParser = require('cookie-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();


const app = express();
app.use(express.json());
app.use(cookieParser()); // handles auth tokens
app.use(cors());


const port = process.env.PORT || 62500;
const dbPath = process.env.DB_PATH || 'db/users.db';
const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET;

async function processRawPassword(p, s) {
    const password = await bcrypt.hash(p, s);
    return password;
}

let db = new sqlite3.Database(dbPath, error => {
    if (error) {console.error(error.message);}
    console.log(`Connected to the database at ${dbPath}`);
});

db.run('CREATE TABLE IF NOT EXISTS users(username UNIQUE, password, salt)'); // initializes new databases

app.post('/authenticate-login', (req, res) => {
    // process incoming username and password data
    db.all(`SELECT * FROM users WHERE username = "${req.body.username}";`, (error, row) => {
        if (error) {
            console.error(error);
        } else if (row[0] === undefined) {
            res.send({message: 'Account does not exist.'});
        }
        else {
            processRawPassword(req.body.password, row[0].salt)
                .then(result => {
                    if (row[0].password === result) {
                        // res.send({message: 'User login successful.'});
                        // send cookie
                        const token = jwt.sign({ username: req.body.username }, accessTokenSecret);
                        res.cookie('AuthToken', token, {httpOnly: true, maxAge: 7200000}).send({message: 'User login successful.'});
                        console.log(`Data received:\nUsername: ${req.body.username}\nPassword: ${req.body.password}`);
                    } else {
                        res.send({message: 'Password is incorrect.'});
                    }   
                });
        }
    });
});

app.post('/register-user', async (req, res) => {
    console.log(`Username: ${req.body.username}\nPassword: ${req.body.password}`);
    const salt = await bcrypt.genSalt();
    const password = await bcrypt.hash(req.body.password, salt);
    db.run(`INSERT INTO users VALUES ('${req.body.username}','${password}','${salt}')`, error => {
        if (error) {
            console.error(error);
            switch(error.errno){
                case 19:
                    res.send({message: 'User registration unsuccessful: username already exists.'});
                    break;
                case 1:
                    res.send({message: 'User registration unsuccesful: sqlite3 error.'});
                    break;
            }
        } else {
            res.send({message: 'User registration successful. You can now login.'});
        }
    });
});

app.post('/logout-user', async (req, res) => {
    req.session.destroy();
    res.send({message: 'User log out successful.'});
});

app.post('/authenticate-token', (req, res) => {
    const token = req.cookies.AuthToken;
    if (!token) {
        res.status(401).send('Session expired.');
    } else {
        jwt.verify(token, accessTokenSecret, (error, parsed) => {
            if (error) {
                res.status(401).send('Invalid token');
            } else {
                res.send({authenticated: true, username: parsed.username});
            }
        });
    }
});

app.listen (port, () => {
    console.log(`Server started and listening on port ${port}!`);
});