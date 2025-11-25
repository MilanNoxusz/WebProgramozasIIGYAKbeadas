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
    res.locals.currentRoute = req.path;
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
app.post('/messages', checkAuth, (req, res) => {
    const username = req.user.username;
    const message = req.body.message;
    const sql = "INSERT INTO messages (username, message) VALUES (?, ?)";

    connection.query(sql, [username, message], (err) => {
        if (err) console.log("Hiba az üzenet mentésekor:", err);
        res.redirect(APP_PATH + '/messages');
    });
});

app.get('/messages', checkAuth, (req, res) => {
    const sql = "SELECT * FROM messages ORDER BY created_at DESC";
    connection.query(sql, (err, results) => {
        if (err) {
            console.log("Hiba az üzenetek betöltésekor:", err);
            results = []; 
        }
        res.render('messages', { messages: results });
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

// --- ADMIN ÉS CRUD (RENDELES TÁBLA: id, pizzanev, darab, felvetel, kiszallitas) ---

// 1. READ: Admin felület betöltése
app.get('/admin', checkAdmin, (req, res) => {
    // Felhasználók listája
    connection.query('SELECT * FROM users', (err, userResults) => {
        if (err) console.log(err);
        
        // Rendelések lekérése
        // Formázzuk a dátumokat stringgé az egyszerűség kedvéért, vagy kezeljük a kliens oldalon
        const sqlOrders = 'SELECT * FROM rendeles ORDER BY id DESC';
        connection.query(sqlOrders, (err2, orderResults) => {
            if (err2) console.log(err2);

            // Pizzák lekérése a lenyíló menühöz
            connection.query('SELECT nev FROM pizza ORDER BY nev ASC', (err3, pizzaResults) => {
                if (err3) console.log(err3);

                res.render('admin', { 
                    users: userResults, 
                    orders: orderResults || [],
                    pizzas: pizzaResults || []
                });
            });
        });
    });
});

// 2. CREATE: Új rendelés hozzáadása
app.post('/admin/rendeles/add', checkAdmin, (req, res) => {
    // Az űrlapról érkező adatok
    const { pizzanev, darab, felvetel, kiszallitas } = req.body;

    const sql = "INSERT INTO rendeles (pizzanev, darab, felvetel, kiszallitas) VALUES (?, ?, ?, ?)";
    connection.query(sql, [pizzanev, darab, felvetel, kiszallitas], (err) => {
        if (err) console.error("Hiba a rendelés mentésekor:", err);
        res.redirect(APP_PATH + '/admin');
    });
});

// 3. UPDATE (Form): Szerkesztő oldal betöltése
app.get('/admin/rendeles/edit/:id', checkAdmin, (req, res) => {
    const id = req.params.id;
    
    connection.query('SELECT * FROM rendeles WHERE id = ?', [id], (err, orderResult) => {
        if (err || orderResult.length === 0) {
            return res.redirect(APP_PATH + '/admin');
        }

        connection.query('SELECT nev FROM pizza ORDER BY nev ASC', (err2, pizzaResults) => {
            res.render('admin_edit', { 
                order: orderResult[0], 
                pizzas: pizzaResults 
            });
        });
    });
});

// 3. UPDATE (Action): Adatok frissítése
app.post('/admin/rendeles/update/:id', checkAdmin, (req, res) => {
    const id = req.params.id;
    const { pizzanev, darab, felvetel, kiszallitas } = req.body;

    const sql = "UPDATE rendeles SET pizzanev = ?, darab = ?, felvetel = ?, kiszallitas = ? WHERE id = ?";
    connection.query(sql, [pizzanev, darab, felvetel, kiszallitas, id], (err) => {
        if (err) console.error("Hiba a frissítéskor:", err);
        res.redirect(APP_PATH + '/admin');
    });
});

// 4. DELETE: Rendelés törlése
app.post('/admin/rendeles/delete/:id', checkAdmin, (req, res) => {
    const id = req.params.id;
    connection.query('DELETE FROM rendeles WHERE id = ?', [id], (err) => {
        if (err) console.log("Hiba a törléskor:", err);
        res.redirect(APP_PATH + '/admin');
    });
});

// Szerver indítása
app.listen(PORT, () => {
    console.log(`A szerver fut a ${PORT}-es porton.`);
    console.log(`Elérhető : http://143.47.98.96${APP_PATH}`);
});