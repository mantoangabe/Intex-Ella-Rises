require("dotenv").config();
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const knexLib = require("knex");
const KnexSessionStore = require("connect-session-knex")(session);
const bcrypt = require("bcryptjs");
const path = require("path");
const crypto = require("crypto");



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
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString("base64");
  next();
});
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          (req, res) => `'nonce-${res.locals.nonce}'`,
          "https://cdn.jsdelivr.net"    // allow Bootstrap JS
        ],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",            // Bootstrap needs this
          "https://cdn.jsdelivr.net"
        ],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
  })
);


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
    const participants = await knex("participants")
      .select("*")
      .orderBy("participant_id", "asc");

    res.render("participantinfo/seeparticipants.ejs", {
      user: req.session.user,    // logged-in user for header
      participants               // list for the table
    });
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).send("Error fetching user data: " + err.message);
  }
});



// Get route for adding participants
app.get("/addparticipant", requireLogin, requireManager, (req, res) => {
  res.render("participantinfo/addparticipant.ejs", { 
    user: req.session.user,
    error: null
  });
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
  res.render('participantinfo/participantresult.ejs', { user: req.session.user }, { user: null, found: false });
});

//Edit page
// Load edit form
app.get("/editparticipant/:id", requireLogin, requireManager, async (req, res) => {
  const id = req.params.id;

  try {
    const participant = await knex("participants")
      .where({ participant_id: id })
      .first();

    if (!participant) {
      return res.status(404).send("User not found");
    }

    // Convert DOB into Date object if needed
    participant.dob = new Date(participant.dob);

    res.render("participantinfo/editparticipant.ejs", { 
      user: req.session.user,   // logged-in user (navbar)
      participant               // the user being edited
    });

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

// DONATION ROUTES

app.get("/donations", requireLogin, async (req, res) => {
  const success = req.query.success === "1";

  res.render("donations/donations", {
    user: req.session.user,
    message: success ? "Donation recorded successfully!" : null
  });
});

app.post("/donations", requireLogin, async (req, res) => {
  const { amount } = req.body;

  try {
    const participantId = req.session.user.id; // ← comes from session

    await knex("donations").insert({
      participant_id: participantId,
      amount,
      donation_date: new Date()
    });

    res.redirect("/donations?success=1");
  } catch (err) {
    console.error("Error saving donation:", err);
    res.status(500).send("Error saving donation");
  }
});

// --------------------------
// ERROR HANDLE 418 PAGE
// --------------------------
app.get("/teapot", (req, res) => {
  res.status(418).send("I'm a teapot ☕");
});

async function syncDonationSequence() {
  try {
    // Get the current max donation_id in the table
    const result = await knex("donations").max("donation_id as max_id");
    const maxId = result[0].max_id || 0;
    const nextVal = maxId + 1;

    // Bump the identity sequence so it doesn't collide
    await knex.raw(
      "SELECT setval('public.donations_donation_id_seq', ?, false);",
      [nextVal]
    );

    console.log(`✅ donations_donation_id_seq synced to start at ${nextVal}`);
  } catch (err) {
    console.error("⚠️ Failed to sync donations sequence:", err);
  }
}

async function syncEventSequence() {
  try {
    const result = await knex("event_occurrences").max("event_occurrence_id as max_id");
    const maxId = result[0].max_id || 0;
    const nextVal = maxId + 1;

    await knex.raw(
      "SELECT setval('public.event_occurrences_event_occurrence_id_seq', ?, false);",
      [nextVal]
    );

    console.log(`✅ event_occurrences_event_occurrence_id_seq synced to start at ${nextVal}`);
  } catch (err) {
    console.error("⚠️ Failed to sync event sequence:", err);
  }
}

// =======================================================
// EVENTS MANAGEMENT ROUTES
// =======================================================

// Show all events
app.get("/events", requireLogin, async (req, res) => {
  try {
    const limit = 25;
    const offset = parseInt(req.query.offset) || 0;

    const events = await knex("event_occurrences as eo")
      .leftJoin("event_templates as et", "eo.event_template_id", "et.event_template_id")
      .select(
        "eo.event_occurrence_id",
        "eo.event_name",
        "eo.start_datetime",
        "eo.end_datetime",
        "eo.location",
        "eo.capacity",
        "eo.registration_deadline",
        "eo.event_template_id",
        "et.event_name as template_name",
        "et.event_type"
      )
      .orderBy("eo.start_datetime", "asc")
      .limit(limit)
      .offset(offset);

    // Count total number of events
    const [{ count }] = await knex("event_occurrences").count("* as count");

    const hasMore = offset + limit < count;

    res.render("events/events", {
      user: req.session.user,
      events,
      offset,
      limit,
      hasMore
    });

  } catch (err) {
    console.error("Error loading events:", err);
    res.status(500).send("Error loading events");
  }
});

// GET add event page
app.get("/addevent", requireLogin, requireManager, async (req, res) => {
  try {
    const templates = await knex("event_templates").select("*");
    res.render("events/addevent", {
      user: req.session.user,
      templates
    });
  } catch (err) {
    console.error("Error loading add event page:", err);
    res.status(500).send("Error loading add event page.");
  }
});

// POST create event
app.post("/addevent", requireLogin, requireManager, async (req, res) => {
  try {
    const data = req.body;

    await knex("event_occurrences").insert({
      event_name: data.event_name,
      start_datetime: data.start_datetime,
      end_datetime: data.end_datetime,
      location: data.location,
      capacity: data.capacity,
      registration_deadline: data.registration_deadline || null,
      event_template_id: data.event_template_id || null
    });

    res.redirect("/events");

  } catch (err) {
    console.error("Error adding event:", err);
    res.status(500).send("Error adding event: " + err.message);
  }
});

// GET edit event
app.get("/editevent/:id", requireLogin, requireManager, async (req, res) => {
  try {
    const event = await knex("event_occurrences")
      .where("event_occurrence_id", req.params.id)
      .first();

    const templates = await knex("event_templates").select("*");

    res.render("events/editevent", {
      user: req.session.user,
      event,
      templates
    });

  } catch (err) {
    console.error("Error loading event edit:", err);
    res.status(500).send("Error loading edit page");
  }
});

// POST edit event
app.post("/editevent/:id", requireLogin, requireManager, async (req, res) => {
  try {
    const data = req.body;

    await knex("event_occurrences")
      .where("event_occurrence_id", req.params.id)
      .update({
        event_name: data.event_name,
        start_datetime: data.start_datetime,
        end_datetime: data.end_datetime,
        location: data.location,
        capacity: data.capacity,
        registration_deadline: data.registration_deadline || null,
        event_template_id: data.event_template_id || null
      });

    res.redirect("/events");

  } catch (err) {
    console.error("Error saving event:", err);
    res.status(500).send("Error saving event");
  }
});

// DELETE event
app.post("/deleteevent/:id", requireLogin, requireManager, async (req, res) => {
  const id = req.params.id;

  try {
    // 1. Delete surveys linked to registrations for this event
    await knex("surveys")
      .whereIn("registration_id", function () {
        this.select("registration_id")
          .from("registrations")
          .where("event_occurrence_id", id);
      })
      .del();

    // 2. Delete registrations linked to this event
    await knex("registrations")
      .where({ event_occurrence_id: id })
      .del();

    // 3. Delete the event
    await knex("event_occurrences")
      .where({ event_occurrence_id: id })
      .del();

    res.redirect("/events");

  } catch (err) {
    console.error("Error deleting event:", err);
    res.status(500).send("Error deleting event");
  }
});



// SEARCH events
app.post("/searchevents", requireLogin, async (req, res) => {
  try {
    const q = req.body.EventSearch;

    const events = await knex("event_occurrences as eo")
      .leftJoin("event_templates as et", "eo.event_template_id", "et.event_template_id")
      .whereILike("eo.event_name", `%${q}%`)
      .orWhereILike("eo.location", `%${q}%`)
      .orWhereILike("et.event_name", `%${q}%`)
      .select(
        "eo.event_occurrence_id",
        "eo.event_name",
        "eo.start_datetime",
        "eo.end_datetime",
        "eo.location",
        "eo.capacity",
        "eo.registration_deadline",
        "eo.event_template_id",
        "et.event_name as template_name",
        "et.event_type"
      )
      .orderBy("eo.start_datetime", "asc");

    res.render("events/events", {
      user: req.session.user,
      events
    });

  } catch (err) {
    console.error("Error searching events:", err);
    res.status(500).send("Error searching events");
  }
});
app.get("/debug", (req, res) => {
  res.json(req.session.user);
});
// --------------------------
// RUN SERVER
// --------------------------
async function startServer() {
  try {
    await syncDonationSequence();
    await syncEventSequence();  // <-- ADD THIS LINE

    app.listen(3000, () => {
      console.log("Server running on port 3000");
    });
  } catch (err) {
    console.error("Failed to start server:", err);
    process.exit(1);
  }
}


startServer();

