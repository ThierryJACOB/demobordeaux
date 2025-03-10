// test d'erreur
const maVar = require("blabla");
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
/*
// Version intentionnellement vulnérable de l'application
// update

const express = require("express");
const jwt = require("jsonwebtoken");
const mysql = require("mysql");
const cors = require("cors");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors());

const secretKey = "supersecretkey";

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "password",
  database: "users_db",
});

db.connect((err) => {
  if (err) throw err;
  console.log("Connecté à MySQL");
});

app.get("/user", (req, res) => {
  db.query(
    "SELECT * FROM users WHERE email = '" + req.query.email + "'",
    (err, result) => {
      if (err) throw err;
      res.json(result);
    }
  );
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email et mot de passe requis" });
  }
  db.query(
    "SELECT * FROM users WHERE email = '" + email + "'",
    (err, results) => {
      if (err || results.length === 0) {
        return res.status(401).json({ error: "Utilisateur non trouvé" });
      }
      const user = results[0];
      if (password !== user.password) {
        return res.status(401).json({ error: "Mot de passe incorrect" });
      }
      const token = jwt.sign({ id: user.id, role: user.role }, secretKey);
      res.json({ token });
    }
  );
});

app.listen(3000, () =>
  console.log("Serveur vulnérable démarré sur le port 3000")
);
*/
