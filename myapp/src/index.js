const express = require("express");
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const swaggerDocument = YAML.load('C:/Users/LENOVO/Desktop/web/myapp/src/swaggerfile.yaml');

const path = require("path");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const axios = require("axios");


const dbPath = path.join(__dirname, "data.db");
const app = express();

app.use(express.json());

let db = null;

const initializeDBAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    app.listen(1344, () => {
      console.log("Server Running at http://localhost:1344/");
    });
  } catch (e) {
    console.log(`DB Error: ${e.message}`);
    process.exit(1);
  }
};

initializeDBAndServer();


function authenticateToken(request, response, next) {
  let jwtToken;
  const authHeader = request.headers["authorization"];
  if (authHeader !== undefined) {
    jwtToken = authHeader.split(" ")[1];
  }
  if (jwtToken === undefined) {
    response.status(401);
    response.send("Invalid JWT Token");
  } else {
    jwt.verify(jwtToken, "MY_SECRET_TOKEN", async (error, payload) => {
      if (error) {
        response.status(401);
        response.send("Invalid JWT Token");
      } else {
        next();
      }
    });
  }
}

// LOGIN USER 

app.post("/login/", async (request, response) => {
  const { username, password } = request.body;
  const selectUserQuery = `SELECT * FROM users WHERE username = '${username}';`;
  const databaseUser = await db.get(selectUserQuery);
  if (databaseUser === undefined) {
    response.status(400);
    response.send("Invalid user");
  } else {
    const isPasswordMatched = await bcrypt.compare(
      password,
      databaseUser.password
    );
    if (isPasswordMatched === true) {
      const payload = {
        username: username,
      };
      const jwtToken = jwt.sign(payload, "MY_SECRET_TOKEN");
      response.send({ jwtToken });
    } else {
      response.status(400);
      response.send("Invalid password");
    }
  }
});


// REGISTER USER

app.post("/register/", async (request, response) => {
  const { username, password, email } = request.body;
  const saltRounds = 15; // Number of salt rounds (can be adjusted based on your security requirements)
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  const selectUserQuery = `SELECT * FROM users WHERE username = '${username}'`;
  const dbUser = await db.get(selectUserQuery);
  if (dbUser === undefined) {
    const createUserQuery = `
      INSERT INTO 
        users (username, password, email) 
      VALUES 
        (
          '${username}', 
            '${hashedPassword}', 
            '${email}'
        )`;
    const dbResponse = await db.run(createUserQuery);
    const newUserId = dbResponse.lastID;
    response.send(`Created new user with ${newUserId}`);
  } else {
    response.status = 400;
    response.send("User already exists");
  }
});
app.get('/data', async (req, res) => {
    try {
        // Fetch data from public API
        const response = await axios.get('https://api.publicapis.org/entries');
        const data = response.data.entries;

        // Extract query parameters for filtering
        const { category, limit } = req.query;

        // Apply filtering based on query parameters
        let filteredData = data;
        if (category) {
            filteredData = filteredData.filter(entry => entry.Category.toLowerCase() === category.toLowerCase());
        }
        if (limit) {
            filteredData = filteredData.slice(0, parseInt(limit));
        }

        // Send filtered data as response
        res.json(filteredData);
    } catch (error) {
        console.error('Error fetching data:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

app.get('/ethbalance/:address', async (req, res) => {
    try {
        // Validate Ethereum address
        if (!web3.utils.isAddress(req.params.address)) {
            return res.status(400).send('Invalid Ethereum address');
        }
        
        const balanceWei = await web3.eth.getBalance(req.params.address);
        const balanceEth = web3.utils.fromWei(balanceWei, 'ether');
        res.send({ balance: balanceEth });
    } catch (error) {
        res.status(500).send('Error fetching balance');
    }
});

