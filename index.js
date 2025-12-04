if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const knexLib = require("knex");
const KnexSessionStore = require("connect-session-knex")(session);
const bcrypt = require("bcrypt");
const path = require("path");
const crypto = require("crypto");



const app = express();

// --------------------------
// DATABASE (PostgreSQL)
// --------------------------
const knex = require("knex")({
  client: "pg",
  connection: {
    host: process.env.RDS_HOSTNAME,
    user: process.env.RDS_USERNAME,
    password: process.env.RDS_PASSWORD,
    database: process.env.RDS_DB_NAME,
    port: process.env.RDS_PORT,
    ssl: { rejectUnauthorized: false }
  },
});

// Force schema so postgres finds your tables
knex.raw('SET search_path TO public');



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

// Get route for Tableau dashboard
app.get("/dashboard", requireLogin, requireManager, (req, res) => {
  res.render("dashboard/dashboard.ejs", { 
    user: req.session.user,
    error: null
  });
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


// MILESTONESS ROUTESS 

// =======================================================
// MILESTONES ROUTES (FULL CRUD)
// =======================================================



// --------------------------
// VIEW ALL MILESTONES
// --------------------------
app.get("/milestones", requireLogin, async (req, res) => {
  try {
    const milestones = await knex("milestones")
      .select("*")
      .orderBy("milestone_id", "asc");

    res.render("milestones/milestones", {
      user: req.session.user,
      milestones,
      nonce: res.locals.nonce
    });

  } catch (err) {
    console.error("Error fetching milestones:", err);
    res.status(500).send("Error fetching milestones");
  }
});

// --------------------------
// SEARCH MILESTONES
// --------------------------
app.post("/searchmilestones", requireLogin, async (req, res) => {
  const rawSearch = req.body.MilestoneSearch || "";
  const q = rawSearch.trim();

  try {
    const milestones = await knex("milestones")
      .where(function () {
        // Always search title
        this.whereILike("title", `%${q}%`);

        // Only search participant_id if q is a NON-empty NUMBER
        if (q !== "" && !isNaN(q)) {
          this.orWhere("participant_id", Number(q));
        }
      })
      .orderBy("milestone_id", "asc");

    res.render("milestones/milestones", {
      user: req.session.user,
      milestones,
      nonce: res.locals.nonce
    });

  } catch (err) {
    console.error("Search error:", err);
    res.status(500).send("Error searching milestones");
  }
});



// --------------------------
// ADD MILESTONE (FORM)
// --------------------------
app.get("/addmilestone", requireLogin, requireManager, async (req, res) => {
  try {
    const titles = await knex("milestones")
      .distinct("title")
      .orderBy("title", "asc");

    const participants = await knex("participants")
      .select("participant_id", "first_name", "last_name")
      .orderBy("first_name", "asc");

    res.render("milestones/addmilestone", {
      user: req.session.user,
      titles,
      participants,
      nonce: res.locals.nonce
    }); 

  } catch (err) {
    console.error("Error loading milestone data:", err);
    res.status(500).send("Error loading milestone data");
  }
});


// --------------------------
// ADD MILESTONE (SUBMIT)
// --------------------------
app.post("/addmilestone", requireLogin, requireManager, async (req, res) => {
  const { participant_id, title, achieved_date } = req.body;

  try {
    await knex("milestones").insert({
      participant_id,
      title,
      achieved_date
    });

    res.redirect("/milestones");

  } catch (err) {
    console.error("Error adding milestone:", err);
    res.status(500).send("Error adding milestone");
  }
});

// --------------------------
// EDIT MILESTONE (FORM)
// --------------------------
app.get("/editmilestone/:id", requireLogin, requireManager, async (req, res) => {
  const id = req.params.id;

  try {
    const milestone = await knex("milestones")
      .where({ milestone_id: id })
      .first();

    if (!milestone) {
      return res.status(404).send("Milestone not found");
    }

    // Load participants for dropdown
    const participants = await knex("participants")
      .select("participant_id", "first_name", "last_name")
      .orderBy("first_name", "asc");

    // Load milestone titles for dropdown OR custom entry
    const titles = await knex("milestones")
      .distinct("title")
      .orderBy("title", "asc");

    res.render("milestones/editmilestone", {
      user: req.session.user,
      milestone,
      participants,
      titles,
      nonce: res.locals.nonce
    });

  } catch (err) {
    console.error("Error loading milestone:", err);
    res.status(500).send("Error loading milestone");
  }
});


// --------------------------
// EDIT MILESTONE (SUBMIT)
// --------------------------
app.post("/editmilestone/:id", requireLogin, requireManager, async (req, res) => {
  const id = req.params.id;
  const { participant_id, title, achieved_date } = req.body;

  try {
    await knex("milestones")
      .where({ milestone_id: id })
      .update({
        participant_id,
        title,
        achieved_date
      });

    res.redirect("/milestones");

  } catch (err) {
    console.error("Error editing milestone:", err);
    res.status(500).send("Error editing milestone");
  }
});

// --------------------------
// DELETE MILESTONE
// --------------------------
app.post("/deletemilestone/:id", requireLogin, requireManager, async (req, res) => {
  const id = req.params.id;

  try {
    await knex("milestones")
      .where({ milestone_id: id })
      .del();

    res.redirect("/milestones");

  } catch (err) {
    console.error("Error deleting milestone:", err);
    res.status(500).send("Error deleting milestone");
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
async function syncMilestoneSequence() {
  try {
    // Get the current max milestone_id
    const result = await knex("milestones").max("milestone_id as max_id");
    const maxId = result[0].max_id || 0;
    const nextVal = maxId + 1;

    // Sync the sequence
    await knex.raw(
      "SELECT setval('public.milestones_milestone_id_seq', ?, false);",
      [nextVal]
    );

    console.log(`✅ milestones_milestone_id_seq synced to start at ${nextVal}`);
  } catch (err) {
    console.error("⚠️ Failed to sync milestone sequence:", err);
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
      .orderBy("eo.event_occurrence_id", "asc")
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
    await syncMilestoneSequence();
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});

  } catch (err) {
    console.error("Failed to start server:", err);
    process.exit(1);
  }
}


startServer();

