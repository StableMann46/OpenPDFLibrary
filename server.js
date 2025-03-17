require("dotenv").config();
const express = require("express");
const multer = require("multer");
const path = require("path");
const bodyParser = require("body-parser");
const session = require("express-session");
const fs = require("fs");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = 3000;

app.use("/uploads", express.static("uploads"));
app.use(express.static("public"));

// Configure session
app.use(session({
    secret: "your-secret-key",
    resave: false,
    saveUninitialized: true
}));

// Middleware for parsing form data
app.use(bodyParser.urlencoded({ extended: true }));

// MySQL Connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect(err => {
    if (err) {
        console.error("Database connection failed: " + err.message);
    } else {
        console.log("Connected to MySQL database.");
    }
});

// Set view engine to EJS
app.set("view engine", "ejs");

// File upload: General uploads (using original file name)
const storage = multer.diskStorage({
    destination: "./uploads/",
    filename: (req, file, cb) => {
        cb(null, file.originalname);
    },
});
const upload = multer({
    storage: storage,
    limits: { fileSize: 10000000 },
}).single("file");

// File upload: Profile picture uploads (saved as username-profile.extension)
const profileStorage = multer.diskStorage({
    destination: "./uploads/",
    filename: (req, file, cb) => {
        cb(null, req.session.user + "-profile" + path.extname(file.originalname));
    },
});
const profileUpload = multer({ storage: profileStorage });

// Home Page Route: Pass username (or null) and fetch user's uploaded files if logged in.
app.get("/", (req, res) => {
    let username = req.session.user || null;
    // If no user is logged in, render the page with empty files array.
    if (!username) {
        return res.render("index", { username, files: [] });
    }
    const query = "SELECT file_name FROM uploads WHERE username = ?";
    db.query(query, [username], (err, results) => {
        if (err) {
            console.error("Database error: " + err.message);
            return res.render("index", { username, files: [] });
        }
        const userFiles = results.map(row => row.file_name);
        res.render("index", { username, files: userFiles });
    });
});

// Login Page
app.get("/login", (req, res) => {
    res.render("login", { username: null, error: null, success: null });
});

// Handle Login with improved error handling
app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.render("login", { username: null, error: "All fields are required!", success: null });
    }
    db.query("SELECT * FROM users WHERE username = ?", [username], async (err, results) => {
        if (err) return res.render("login", { username: null, error: "Database error. Try again.", success: null });
        if (results.length === 0) return res.render("login", { username: null, error: "Invalid credentials. Try again.", success: null });
        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.render("login", { username: null, error: "Invalid credentials. Try again.", success: null });
        }
        req.session.user = user.username;
        req.session.save((err) => {
            if (err) {
                return res.render("login", { username: null, error: "Session error. Try again.", success: null });
            }
            res.redirect("/");
        });
    });
});

// Signup Page
app.get("/signup", (req, res) => {
    res.render("signup", { username: null, error: null, success: null });
});

// Handle Signup with error handling & password validation
app.post("/signup", async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.render("signup", { username: null, error: "All fields are required!", success: null });
    }
    if (password.length < 6) {
        return res.render("signup", { username: null, error: "Password must be at least 6 characters long!", success: null });
    }
    db.query("SELECT * FROM users WHERE username = ?", [username], async (err, results) => {
        if (err) return res.render("signup", { username: null, error: "Database error. Try again.", success: null });
        if (results.length > 0) {
            return res.render("signup", { username: null, error: "Username already exists. Try a different one.", success: null });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        db.query("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], (err, result) => {
            if (err) return res.render("signup", { username: null, error: "Database error. Try again.", success: null });
            return res.render("signup", { username: null, error: null, success: "Account created successfully! You can now log in." });
        });
    });
});

// Profile Page (Protected): Fetch user's email and profile picture (if available)
app.get("/profile", (req, res) => {
    if (!req.session.user) return res.redirect("/login");
    db.query("SELECT email, profilePic FROM users WHERE username = ?", [req.session.user], (err, results) => {
        if (err || results.length === 0) {
            return res.render("profile", { username: req.session.user, profilePic: "default.jpg", email: "" });
        }
        const userData = results[0];
        res.render("profile", { 
            username: req.session.user, 
            profilePic: userData.profilePic || "default.jpg",
            email: userData.email || ""
        });
    });
});

// Handle Username Change
app.post("/update-username", (req, res) => {
    if (!req.session.user) return res.redirect("/login");
    const newUsername = req.body.newUsername;
    const oldUsername = req.session.user;
    db.query("SELECT * FROM users WHERE username = ?", [newUsername], (err, results) => {
        if (err) return res.send("Database error.");
        if (results.length > 0) return res.send("Username already taken. <a href='/profile'>Try again</a>");
        db.query("UPDATE users SET username = ? WHERE username = ?", [newUsername, oldUsername], (err) => {
            if (err) return res.send("Database error.");
            req.session.user = newUsername;
            res.redirect("/profile");
        });
    });
});

// Handle Password Change
app.post("/update-password", async (req, res) => {
    if (!req.session.user) return res.redirect("/login");
    const { currentPassword, newPassword } = req.body;
    db.query("SELECT password FROM users WHERE username = ?", [req.session.user], async (err, results) => {
        if (err) return res.send("Database error.");
        if (results.length === 0) return res.redirect("/logout");
        const storedPassword = results[0].password;
        const isMatch = await bcrypt.compare(currentPassword, storedPassword);
        if (!isMatch) return res.send("Incorrect current password. <a href='/profile'>Try again</a>");
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        db.query("UPDATE users SET password = ? WHERE username = ?", [hashedPassword, req.session.user], (err) => {
            if (err) return res.send("Database error.");
            res.redirect("/profile");
        });
    });
});

app.post("/update-email", (req, res) => {
    if (!req.session.user) return res.redirect("/login");
    const newEmail = req.body.newEmail;
    db.query("UPDATE users SET email = ? WHERE username = ?", [newEmail, req.session.user], (err) => {
        if (err) return res.send("Database error.");
        res.redirect("/profile");
    });
});

// Profile Page (Protected)
app.get("/profile", (req, res) => {
    if (!req.session.user) {
        return res.redirect("/login");
    }
    // Query to fetch email and profilePic for the logged-in user
    db.query("SELECT email, profilePic FROM users WHERE username = ?", [req.session.user], (err, results) => {
        if (err || results.length === 0) {
            // Fallback if something goes wrong: use default values.
            return res.render("profile", { 
                username: req.session.user, 
                profilePic: "default.jpg", 
                email: "" 
            });
        }
        const userData = results[0];
        res.render("profile", { 
            username: req.session.user, 
            profilePic: userData.profilePic || "default.jpg",
            email: userData.email || ""
        });
    });
});

// Handle Logout
app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/login");
    });
});

// Handle File Upload
app.post("/upload", (req, res) => {
    if (!req.session.user) return res.redirect("/login");
    upload(req, res, (err) => {
        if (err) return res.send("File upload failed. Error: " + err.message);
        const query = "INSERT INTO uploads (username, file_name) VALUES (?, ?)";
        db.query(query, [req.session.user, req.file.originalname], (err) => {
            if (err) console.error("Database error: " + err.message);
            res.redirect("/");
        });
    });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server started at http://localhost:${PORT}`);
});
