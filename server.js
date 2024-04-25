const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();
const port = 3000;
const mysql = require("mysql2/promise");
const bcrypt = require('bcrypt');

const TOKEN_SECRET = 'mySuperSecret'; 

app.use(express.json());
app.use(express.urlencoded({ extended: false }));


function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.sendStatus(401);

  jwt.verify(token, TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

async function getDBConnnection() {
  return await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "restapi",
  });
}

function isValidUserData(userData) {
  const { username, name, password, email } = userData;
  return username && name && password && email;
}


app.post('/users', async function(req, res) {

  try {
    if (!isValidUserData(req.body)) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    const { username, name, password, email } = req.body;

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    let connection = await getDBConnnection();
    const sql = "INSERT INTO users (username, name, password, email) VALUES (?, ?, ?, ?)";
    const [result] = await connection.execute(sql, [username, name, hashedPassword, email]);
    
    
    const payload = { username: username };
    const token = jwt.sign(payload, TOKEN_SECRET, { expiresIn: '2m' });
    res.json({payload , token });
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});


app.put('/users/:id', authenticateToken, async function (req, res) {
  try {
    const userId = req.params.id;
    const { username, name, password, email } = req.body;

    if (!userId || !isValidUserData({ username, name, password, email })) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const connection = await getDBConnnection();
    
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const sql = "UPDATE users SET username = ?, name = ?, password = ?, email = ? WHERE id = ?";
    const [result] = await connection.execute(sql, [username, name, hashedPassword, email, userId]);

    if (result && result.affectedRows > 0) {
      res.sendStatus(200);
    } else {
      res.status(400).send('User with specified ID not found');
    }
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});


app.get('/users', async function(req, res) {
  try {
    let connection = await getDBConnnection();
    let sql = "SELECT * FROM users"; 
    let [results] = await connection.execute(sql);
    res.json(results);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});



// Anropas med GET /gen-hash?password=kalleanka
app.get("/gen-hash", async (req, res) => {
  const salt = await bcrypt.genSalt(10) // genererar ett salt till hashning
  const hashedPassword = await bcrypt.hash(req.query.password, salt) //hashar lösenordet
  res.send(hashedPassword) //Sickar tillbaka hashen/hashvärdet
})

app.post('/login', async function(req, res) {
  try {
    const { username, password } = req.body;
    let connection = await getDBConnnection();
    const sql = "SELECT * FROM users WHERE username = ?";
    const [results] = await connection.execute(sql, [username]);

    if (results.length === 0) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const user = results[0];
    const hashedPasswordFromDB = user.password;
    const passwordMatch = await bcrypt.compare(password, hashedPasswordFromDB);

    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const payload = {
      sub: user.id,
      name: user.name
    };
    const token = jwt.sign(payload, TOKEN_SECRET);

    res.json({ token });
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});


app.get("/auth-test", function (req, res) {
  let authHeader = req.headers["authorization"]; //Hämtar värdet (en sträng med token) från authorization headern i requesten
  
  if (authHeader === undefined) {
    res.status(401).send("Auth token missing.")
  }
  
  let token = authHeader.slice(7); // Tar bort "BEARER " som står i början på strängen.
  console.log(" token: ", token);

  let decoded;
  try {
    // Verifiera att detta är en korrekt token. Den ska vara:
    // * skapad med samma secret
    // * omodifierad
    // * fortfarande giltig
    decoded = jwt.verify(token, TOKEN_SECRET);
  } catch (err) {
    // Om något är fel med token så kastas ett error.

    console.error(err); //Logga felet, för felsökning på servern.

    res.status(401).send("Invalid auth token");
  }

  res.send(decoded); // Skickar tillbaka den avkodade, giltiga, tokenen.
});

app.get('/', (req, res) => {
  res.send(`
  <h1>Dokumentation</h1>
  <ul>
    <li><a href="/users"> GET users</a><li>
    <li><a href="/auth-test">GET auth-test</a><li>
    <li><a href="/users/id">PUT users/id</a><li>
    <li><a href="/users">POST users</a><li>
    <li><a href="/login">POST login</a><li>
  </ul>
    `);});

app.listen(port, () => {
  console.log(`Servern lyssnar på port ${port}`);
});
