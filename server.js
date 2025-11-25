const express = require('express');
const mysql = require('mysql2');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const crypto = require('crypto');
const path = require('path');
const bodyParser = require('body-parser');

const app = express();

const PORT = 4027; 
const APP_PATH = '/app027';

const dbOptions = {
    host: 'localhost',
    user: 'studb027',
    password: 'abc123', 
    database: 'db027' 
};
const connection = mysql.createConnection(dbOptions);

app.set('view engine', 'ejs');

// --- ÚTVONAL TISZTÍTÓ MIDDLEWARE ---
app.use((req, res, next) => {
    if (req.url.startsWith(APP_PATH)) {
        req.url = req.url.slice(APP_PATH.length) || '/';
    }
    res.locals.appPath = APP_PATH;
    next();
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const sessionStore = new MySQLStore(dbOptions);

app.use(session({
    key: 'session_cookie_name',
    secret: 'titkos_kulcs_string',
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 
    }
}));

// --- PASSPORT KONFIGURÁCIÓ ---
function genPasswordSimple(password) {
    return crypto.createHash('sha512').update(password).digest('hex'); 
}

app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(function(username, password, done) {
    connection.query('SELECT * FROM users WHERE username = ?', [username], function(err, results) {
        if (err) return done(err);
        if (results.length === 0) return done(null, false);

        const user = results[0];
        const hashVerify = crypto.createHash('sha512').update(password).digest('hex');
        
        if (user.hash === hashVerify) {
            return done(null, user);
        } else {
            return done(null, false);
        }
    });
}));

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser((id, done) => {
    connection.query('SELECT * FROM users WHERE id = ?', [id], (err, results) => done(err, results[0]));
});

app.use(function(req, res, next) {
    res.locals.isAuthenticated = req.isAuthenticated();
    res.locals.currentUser = req.user;
    next();
});

function checkAuth(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect(APP_PATH + '/login');
}

function checkAdmin(req, res, next) {
    if (req.isAuthenticated() && req.user.isAdmin == 1) return next();
    res.redirect(APP_PATH + '/');
}


// --- ÚTVONALAK (ROUTES) ---

app.get('/', (req, res) => {
    res.render('index');
});

app.get('/offers', (req, res) => {
    // 1. Lekérdezés: 6 random pizza árral együtt (JOIN)
    const sqlPizzas = `
        SELECT p.nev, p.kategorianev, p.vegetarianus, k.ar 
        FROM pizza p 
        JOIN kategoria k ON p.kategorianev = k.nev 
        ORDER BY RAND() 
        LIMIT 6
    `;

    connection.query(sqlPizzas, (err, pizzaResults) => {
        if (err) {
            console.error("Hiba a pizzák lekérdezésekor:", err);
            return res.redirect(APP_PATH + '/');
        }

        // 2. Lekérdezés: Utolsó 5 rendelés
        const sqlOrders = `SELECT * FROM rendeles ORDER BY id DESC LIMIT 5`;
        
        connection.query(sqlOrders, (err2, orderResults) => {
            if (err2) {
                console.error("Hiba a rendelések lekérdezésekor:", err2);
                // Ha hiba van, akkor is megjelenítjük a pizzákat, csak rendelés nélkül
                return res.render('offers', { pizzas: pizzaResults, orders: [] });
            }

            res.render('offers', { 
                pizzas: pizzaResults, 
                orders: orderResults 
            });
        });
    });
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', (req, res) => {
    const hash = genPasswordSimple(req.body.password);
    connection.query('INSERT INTO users (username, hash, isAdmin) VALUES (?, ?, 0)', 
    [req.body.username, hash], function(err) {
        if (err) console.log(err);
        res.redirect(APP_PATH + '/login');
    });
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', passport.authenticate('local', {
    successRedirect: APP_PATH + '/',
    failureRedirect: APP_PATH + '/login'
}));

app.get('/logout', (req, res, next) => {
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect(APP_PATH + '/');
    });
});

app.get('/messages', checkAuth, (req, res) => {
    res.render('messages');
});

app.get('/admin', checkAdmin, (req, res) => {
    connection.query('SELECT * FROM users', (err, results) => {
        res.render('admin', { users: results });
    });
});

// Szerver indítása
app.listen(PORT, () => {
    console.log(`A szerver fut a ${PORT}-es porton.`);
    console.log(`Elérhető : http://143.47.98.96${APP_PATH}`);
});