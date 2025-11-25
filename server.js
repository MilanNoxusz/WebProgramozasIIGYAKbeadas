const express = require('express');
const mysql = require('mysql2');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const crypto = require('crypto');
const path = require('path');
const bodyParser = require('body-parser');

// EZEKET ÍRD ÁT A SAJÁT ADATAIDRA! (neked )
const PORT = 4027; 
const BASE_PATH = '/app027'; 

const dbOptions = {
    host: 'localhost',
    user: 'studb027',
    password: 'abc123', 
    database: 'db027' 
};

app.set('view engine', 'ejs');

// Statikus fájlok (CSS, Képek) kiszolgálása a 'public' mappából
app.use(express.static(path.join(__dirname, 'public')));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const sessionStore = new MySQLStore(dbOptions);
const connection = mysql.createConnection(dbOptions);

app.use(session({
    key: 'session_cookie_name',
    secret: 'titkos_kulcs_string',
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 // 1 nap
    }
}));

function genPassword(password) {
    var salt = crypto.randomBytes(32).toString('hex');
    var genHash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    return { salt: salt, hash: genHash };
}
function genPasswordSimple(password) {
    return crypto.createHash('sha512').update(password).digest('hex'); 
}

// --- 3. PASSPORT (BIZTONSÁG) BEÁLLÍTÁSA ---
// Jelszó titkosító függvények (a PDF alapján)
function genPassword(password) {
    var salt = crypto.randomBytes(32).toString('hex');
    var genHash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    return { salt: salt, hash: genHash };
}
// Egyszerűsített hash tárolás a példa kedvéért (salt+hash egy stringben):
function genPasswordSimple(password) {
    // A PDF egyszerűsített példáját követjük, de a 'salt' tárolását a DB schema nem írta külön,
    // így a hash-t generáljuk csak.
    return crypto.createHash('sha512').update(password).digest('hex'); 
}

// Passport inicializálás
app.use(passport.initialize());
app.use(passport.session());

// Stratégia: Hogyan lépünk be?
passport.use(new LocalStrategy(function(username, password, done) {
    connection.query('SELECT * FROM users WHERE username = ?', [username], function(err, results) {
        if (err) return done(err);
        if (results.length === 0) return done(null, false); // Nincs ilyen felhasználó

        const user = results[0];
        // Jelszó ellenőrzés
        const hashVerify = crypto.createHash('sha512').update(password).digest('hex');
        
        if (user.hash === hashVerify) {
            return done(null, user); // Sikeres belépés
        } else {
            return done(null, false); // Hibás jelszó
        }
    });
}));

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    connection.query('SELECT * FROM users WHERE id = ?', [id], function(err, results) {
        done(err, results[0]);
    });
});

// Middleware, hogy a 'user' objektum minden EJS fájlban elérhető legyen
app.use(function(req, res, next) {
    res.locals.isAuthenticated = req.isAuthenticated();
    res.locals.currentUser = req.user;
    next();
});

// Csak bejelentkezett felhasználóknak
function checkAuth(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
}

// Csak Adminoknak
function checkAdmin(req, res, next) {
    if (req.isAuthenticated() && req.user.isAdmin == 1) return next();
    res.redirect('/'); // Vagy hibaoldalra
}


// Főoldal
app.get('/', (req, res) => {
    res.render('index');
});

// Regisztráció oldal
app.get('/register', (req, res) => {
    res.render('register');
});

// Regisztráció feldolgozása
app.post('/register', (req, res) => {
    const hash = genPasswordSimple(req.body.password);
    // Alapból isAdmin = 0 (Látogató)
    connection.query('INSERT INTO users (username, hash, isAdmin) VALUES (?, ?, 0)', 
    [req.body.username, hash], function(err) {
        if (err) console.log(err);
        res.redirect('/login');
    });
});

// Bejelentkezés oldal
app.get('/login', (req, res) => {
    res.render('login');
});

// Bejelentkezés feldolgozása
app.post('/login', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login'
}));

// Kijelentkezés
app.get('/logout', (req, res, next) => {
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/');
    });
});

// Üzenetek (Csak regisztráltaknak)
app.get('/messages', checkAuth, (req, res) => {
    res.render('messages');
});

// Admin oldal (Csak adminoknak)
app.get('/admin', checkAdmin, (req, res) => {
    // Itt listázhatnánk pl. a felhasználókat
    connection.query('SELECT * FROM users', (err, results) => {
        res.render('admin', { users: results });
    });
});


server.listen(PORT, () => {
    console.log(`A szerver fut a ${PORT}-es porton.`);
    console.log(`Elérhető : http://143.47.98.96${BASE_PATH}`);
});