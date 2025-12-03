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
    message: success ? "Donation recorded successfully! Thank you for your generosity!" : null
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

// Get route for Tableau dashboard
app.get("/dashboard", requireLogin, requireManager, (req, res) => {
  res.render("dashboard/dashboard.ejs", { 
    user: req.session.user,
    error: null
  });
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
// Survey Routes

// --------------------------
// SURVEYS (POST-EVENT)
// --------------------------
app.get("/surveys", requireLogin, async (req, res) => {
  try {
    const search = req.query.search || "";
    const loggedInId = req.session.user.id;
    const isAdmin = req.session.user.role === "admin";

    // Base query
    let query = knex("surveys")
      .join("registrations", "surveys.registration_id", "registrations.registration_id")
      .join("participants", "surveys.participant_id", "participants.participant_id")
      .join("event_occurrences", "registrations.event_occurrence_id", "event_occurrences.event_occurrence_id")
      .join("event_templates", "event_occurrences.event_template_id", "event_templates.event_template_id")
      .select(
        "surveys.*",
        "participants.first_name",
        "participants.last_name",
        "event_templates.event_name",
        "event_occurrences.start_datetime"
      );

    // ⭐ NORMAL USER → ONLY THEIR SURVEYS
    if (!isAdmin) {
      query = query.where("surveys.participant_id", loggedInId);
    }

    // ⭐ SEARCH FILTER
    if (search.trim() !== "") {
      query = query.andWhere(builder =>
        builder
          .where("participants.first_name", "ILIKE", `%${search}%`)
          .orWhere("participants.last_name", "ILIKE", `%${search}%`)
          .orWhereRaw(
            "participants.first_name || ' ' || participants.last_name ILIKE ?",
            [`%${search}%`]
          )
          .orWhere("event_templates.event_name", "ILIKE", `%${search}%`)
      );
    }

    const surveys = await query.orderBy("surveys.survey_id", "asc");

    res.render("surveys/surveys.ejs", {
      user: req.session.user,
      surveys,
      search
    });

  } catch (err) {
    console.error("Survey list error:", err);
    res.status(500).send("Error loading surveys");
  }
});



// --------------------------
// ADD SURVEY FORM (ADMIN OR USER)
// --------------------------
// --------------------------
// ADD SURVEY FORM
// --------------------------
app.get("/surveys/add", requireLogin, async (req, res) => {
  try {
    const loggedInId = req.session.user.id;
    const isAdmin = req.session.user.role === "admin";

    let registrationsQuery = knex("registrations")
      .join("participants", "registrations.participant_id", "participants.participant_id")
      .join("event_occurrences", "registrations.event_occurrence_id", "event_occurrences.event_occurrence_id")
      .join("event_templates", "event_occurrences.event_template_id", "event_templates.event_template_id")
      .select(
        "registrations.registration_id",
        "participants.participant_id",
        "participants.first_name",
        "participants.last_name",
        "event_templates.event_name",
        "event_occurrences.start_datetime"
      )
      .orderBy("event_occurrences.start_datetime", "desc");

    // If not admin → only show this user's registrations
    if (!isAdmin) {
      registrationsQuery = registrationsQuery.where("registrations.participant_id", loggedInId);
    }

    const registrations = await registrationsQuery;

    let participantList = [];
    if (isAdmin) {
      participantList = await knex("participants")
        .select("participant_id", "first_name", "last_name")
        .orderBy("first_name", "asc")
        .orderBy("last_name", "asc");
    }

    res.render("surveys/addSurvey.ejs", {
      user: req.session.user,
      registrations,
      participantList,
      error: null
    });

  } catch (err) {
    console.error("Error loading survey form:", err);
    res.status(500).send("Error loading survey form");
  }
});




app.post("/surveys/add", requireLogin, async (req, res) => {
  try {
    const isAdmin = req.session.user.role === "admin";
    const loggedInId = req.session.user.id;

    const {
      registration_id,
      satisfaction_score,
      usefulness_score,
      instructor_score,
      nps_bucket,
      comments
    } = req.body;

    // ------------------------------------
    // 1. Get participant_id FROM REGISTRATION
    // ------------------------------------
    const registration = await knex("registrations")
      .where({ registration_id })
      .first();

    if (!registration) {
      return res.status(400).send("Invalid registration.");
    }

    // Non-admins are only allowed to submit surveys for their own registrations
    if (!isAdmin && registration.participant_id !== loggedInId) {
      return res.status(400).send("Invalid registration for this user.");
    }

    const participant_id = registration.participant_id;

    // ------------------------------------
    // 2. VALIDATE SCORES
    // ------------------------------------
    const sat = Number(satisfaction_score);
    const use = Number(usefulness_score);
    const inst = Number(instructor_score);

    if (![sat, use, inst].every(n => Number.isFinite(n) && n >= 1 && n <= 5)) {
      return res.status(400).send("Scores must be integers between 1 and 5.");
    }

    const overall_score = (sat + use + inst) / 3;

    // ------------------------------------
    // 3. INSERT SURVEY
    // ------------------------------------
    await knex("surveys").insert({
      registration_id,
      participant_id,
      satisfaction_score: sat,
      usefulness_score: use,
      instructor_score: inst,
      overall_score,
      nps_bucket,
      comments: comments || "",
      submission_date: new Date()
    });

    res.redirect("/surveys");

  } catch (err) {
    console.error("Add survey error:", err);
    res.status(500).send("Error adding survey");
  }
});









app.get("/surveys/edit/:id", requireLogin, requireManager, async (req, res) => {
  try {
    const survey = await knex("surveys")
      .where("survey_id", req.params.id)
      .first();

    if (!survey) return res.status(404).send("Survey not found");

    res.render("surveys/editSurvey.ejs", {
      user: req.session.user,
      survey
    });

  } catch (err) {
    console.error("Edit survey load error:", err);
    res.status(500).send("Error loading edit page");
  }
});

app.post("/surveys/edit/:id", requireLogin, requireManager, async (req, res) => {
  try {
    const {
      satisfaction_score,
      usefulness_score,
      instructor_score,
      nps_bucket,
      comments
    } = req.body;

    // Convert to numbers & compute average
    const overall_score =
      (Number(satisfaction_score) +
       Number(usefulness_score) +
       Number(instructor_score)) / 3;

    await knex("surveys")
      .where("survey_id", req.params.id)
      .update({
        satisfaction_score,
        usefulness_score,
        instructor_score,
        overall_score,
        nps_bucket,
        comments
      });

    res.redirect("/surveys");

  } catch (err) {
    console.error("Survey update error:", err);
    res.status(500).send("Error updating survey");
  }
});


app.post("/surveys/delete/:id", requireLogin, requireManager, async (req, res) => {
  try {
    await knex("surveys")
      .where("survey_id", req.params.id)
      .del();

    res.redirect("/surveys");
  } catch (err) {
    console.error("Survey delete error:", err);
    res.status(500).send("Error deleting survey");
  }
});









// --------------------------
// RUN SERVER
// --------------------------
async function startServer() {
  try {
    // Fix sequence on startup so inserts don't break
    await syncDonationSequence();

    app.listen(3000, () => {
      console.log("Server running on port 3000");
    });
  } catch (err) {
    console.error("Failed to start server:", err);
    process.exit(1);
  }
}

startServer();

