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
  if (!req.session.user || req.session.user.role !== "admin") {
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
    return res.render("auth/login", { error_message: "Missing username or password" });
  }

  try {
    const user = await knex("participants")
      .select("email", "password", "role", "first_name", "participant_id")
      .where({ email: username })
      .first();

    if (!user) {
      return res.render("auth/login", { error_message: "Invalid login" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.render("auth/login", { error_message: "Invalid login" });
    }
    req.session.user = {
      id: user.participant_id,
      name: user.first_name,
      role: user.role
    };

    res.redirect("/");
  } catch (err) {
    console.error("Login error:", err);
    res.render("auth/login", { error_message: "Invalid login" });
  }
});





app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// --------------------------
// Participant Routes
// --------------------------
app.get("/participants", requireLogin, requireManager, async (req, res) => {
  try {
    const user = await knex('participants').select('*').orderBy('participant_id', 'asc');
    
    // 2. ONLY render the page once, with the fetched data
    res.render('participantinfo/seeparticipants.ejs', { 
        participants: user, // Use a clear variable name like 'participants'
        role: req.session.user.role

    }); 
    
  } catch (err) {
    // 3. Handle errors gracefully and send a single error response
    console.error('Error fetching users:', err);
    res.status(500).send('Error fetching user data: ' + err.message);
  }
});
// Get route for adding participants
app.get("/addparticipant", requireLogin, requireManager, (req, res) => {
  res.render("participantinfo/addparticipant.ejs", { error: null });
});

// POST route for adding participants
app.post("/addparticipant", async (req, res) => {
  try {
    const { email, password, first_name, last_name, dob, city, state, zip, school_or_employer, phone, role, field_of_interest } = req.body;

    // 1. Hash password
    const hashedPassword = await bcrypt.hash(password, 10); // 10 = salt rounds

    // 2. Insert into the DB
    await knex("participants").insert({
      email,
      password: hashedPassword,    // store hashed password
      first_name,
      last_name,
      dob,
      city,
      state,
      zip,
      school_or_employer,
      phone,
      role,
      field_of_interest
    });

    res.redirect("/participants");

  } catch (err) {
    console.error(err);
    res.render("participantinfo/addparticipant.ejs", { error: "Error adding participant." });
  }
});
app.post("/deleteparticipant/:id", requireLogin, requireManager, async (req, res) => {
  const participantId = req.params.id;
  try {
    await knex("participants").where({ participant_id: participantId }).del();
    res.redirect("/participants");
  } catch (err) {
    console.error("Error deleting participant:", err);
    res.status(500).send("Error deleting participant.");
  }
});
//Search route
app.post('/searchparticipants', requireLogin, requireManager, async (req, res) => {
  const UserSearch = req.body.UserSearch;

  try {
    const result = await knex('participants')
      .select('*')
      .where({ email: UserSearch })
      .first();

    if (result) {
      res.render('participantinfo/participantresult.ejs', { user: result, found: true });
    } else {
      res.render('participantinfo/participantresult.ejs', { user: null, found: false, searchTerm: UserSearch });
    }
  } catch (err) {
    console.error('Error searching users:', err);
    res.status(500).send('Error searching for users');
  }
});

// Result page
app.get('/participantresult', requireLogin, requireManager, (req, res) => {
  res.render('participantinfo/participantresult.ejs', { user: null, found: false });
});
//Edit page
// Load edit form
app.get("/editparticipant/:id", requireLogin, requireManager, async (req, res) => {
  const id = req.params.id;

  try {
    const user = await knex("participants").where({ participant_id: id }).first();

    if (!user) {
      return res.status(404).send("User not found");
    }

    // Convert DOB into proper JS Date object if needed
    user.dob = new Date(user.dob);

    res.render("participantinfo/editparticipant.ejs", { user });
  } catch (err) {
    console.error("Error loading edit page:", err);
    res.status(500).send("Error loading edit page");
  }
});
// Update participant info
app.post("/update/:id", requireLogin, requireManager, async (req, res) => {
  const id = req.params.id;

  try {
    const {
      first_name,
      last_name,
      email,
      dob,
      city,
      state,
      zip,
      school_or_employer,
      phone,
      role,
      field_of_interest,
      password // optional
    } = req.body;

    let updateData = {
      first_name,
      last_name,
      email,
      dob,
      city,
      state,
      zip,
      school_or_employer,
      phone,
      role,
      field_of_interest
    };

    // Only update password if a new one is provided
    if (password && password.trim() !== "") {
      const hashedPassword = await bcrypt.hash(password, 10);
      updateData.password = hashedPassword;
    }

    await knex("participants")
      .where({ participant_id: id })
      .update(updateData);

    res.redirect("/participants");

  } catch (err) {
    console.error("Error updating participant:", err);
    res.status(500).send("Error updating participant");
  }
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
