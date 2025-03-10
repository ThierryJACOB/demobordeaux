// test d'erreur
const maVar = require("blabla");
db.query();
// version de Copilot
const express = require("express");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2/promise");
const cors = require("cors");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors());

const secretKey = process.env.SECRET_KEY;

const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
};

const dbConnection = mysql.createPool(dbConfig);

app.get("/user", async (req, res) => {
  try {
    const [rows] = await dbConnection.query("SELECT * FROM users WHERE email = ?", [req.query.email]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password required" });
  }
  try {
    const [results] = await dbConnection.query("SELECT * FROM users WHERE email = ?", [email]);
    if (results.length === 0) {
      return res.status(401).json({ error: "User not found" });
    }
    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Incorrect password" });
    }
    const token = jwt.sign({ id: user.id, role: user.role }, secretKey);
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.listen(3000, () => {
  console.log("Secure server started on port 3000");
});

// version d origine
