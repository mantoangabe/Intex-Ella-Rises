require("dotenv").config();
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const knexLib = require("knex");
const KnexSessionStore = require("connect-session-knex")(session);
const bcrypt = require("bcryptjs");
const path = require("path");



const app = express();

// --------------------------
// DATABASE (PostgreSQL)
// --------------------------
const knex = require("knex")({
  client: "pg",
  connection: {
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "postgres",
    password: process.env.DB_PASSWORD || "admin",
    database: process.env.DB_NAME || "ellarises",
    port: process.env.DB_PORT || 5432,
  },
});

// --------------------------
// MIDDLEWARE
// --------------------------
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(helmet());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "secret-change-this",
    resave: false,
    saveUninitialized: false,
    store: new KnexSessionStore({ knex, tablename: "sessions" }),
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

// --------------------------
// VIEW ENGINE
// --------------------------
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "views", "public")));

app.use("/images", express.static(path.join(__dirname, "images")));

// --------------------------
// AUTH HELPERS
// --------------------------
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

function requireManager(req, res, next) {
  if (!req.session.user || req.session.user.role !== "manager") {
    return res.status(403).send("Forbidden");
  }
  next();
}

// --------------------------
// PUBLIC PAGES
// --------------------------
app.get("/", (req, res) => {
  res.render("index", { user: req.session.user });
});

app.get("/visitor-donation", (req, res) => {
  res.render("public/visitorDonation");
});

// --------------------------
// AUTH ROUTES
// --------------------------
app.get("/login", (req, res) => {
  res.render("auth/login", { error: null });
});



app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.render("login", { error_message: "Missing username or password" });
  }

  try {
    const user = await knex("participants")
      .select("email", "password", "role", "first_name", "id")
      .where({ email: username })   // <--  match form username to DB email
      .first();

    if (!user) {
      return res.render("login", { error_message: "Invalid login" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.render("login", { error_message: "Invalid login" });
    }

    req.session.isLoggedIn = true;
    req.session.username = user.first_name;
    req.session.role = user.role;
    req.session.id = user.id;

    res.redirect("/");
  } catch (err) {
    console.error("Login error:", err);
    res.render("login", { error_message: "Invalid login" });
  }
});



app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// --------------------------
// Participant Routes
// --------------------------
app.get("/seeparticipants", requireLogin, requireManager, async (req, res) => {
  try {
    const user = await db('participants').select('*').orderBy('participant_id', 'asc');
    
    // 2. ONLY render the page once, with the fetched data
    res.render('participantinfo/seeparticipants.ejs', { 
        participants: user, // Use a clear variable name like 'participants'
        role: req.session.level // Pass user role to the view
    }); 
    
  } catch (err) {
    // 3. Handle errors gracefully and send a single error response
    console.error('Error fetching users:', err);
    res.status(500).send('Error fetching user data: ' + err.message);
  }
  // The original line 'res.render("participantinfo/seeparticipants.ejs");' is removed.
});
// --------------------------
// ERROR HANDLE 418 PAGE
// --------------------------
app.get("/teapot", (req, res) => {
  res.status(418).send("I'm a teapot ☕");
});

// --------------------------
// RUN SERVER
// --------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running on port", PORT));
