import express from "express";
import bodyparser from "body-parser";
import jwt from "jsonwebtoken";
import redis from "redis";

const JWT_SECRET = "Ultra-secure-secret";

const app = express();
app.use(bodyparser.urlencoded({ extended: false }));
app.use(bodyparser.json());

let client = null;

(async () => {
  client = redis.createClient();

  client.on("error", (err) => {
    console.log(err);
  });
  client.on("connect", () => {
    console.log("Redis connected!");
  });

  await client.connect();
})();

// JWT middleware
const authenticateToken = async (request, response, next) => {
  const authHeader = request.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  // token provided?
  if (token == null)
    return response.status(403).send({
      message: "No token provided",
    });

  // token in blacklist?
  let blacklist = await client.lRange("blacklist", 0, -1);
  if (blacklist.indexOf(token) > -1) {
    return response.status(403).send({
      message: "Token in blacklist",
    });
  }

  // token valid?
  jwt.verify(token, JWT_SECRET, (error, user) => {
    if (error) {
      return response.status(401).send({
        status: "error",
        message: error.message,
      });
    }

    request.userId = user.username;
    request.tokenExp = user.exp;
    request.token = token;

    next();
  });
};

app.post("/createUser", (request, response) => {
  const token = generateAccessToken({ username: request.body.username });
  response.json(token);
});

app.get("/", authenticateToken, (request, response) => {
  return response.status(200).send("Authentication successful");
});

app.post("/logout", authenticateToken, async (request, response) => {
  await client.lPush("blacklist", request.token);
  return response.status(200).send("Token invalidated");
});

const generateAccessToken = (username) => {
  return jwt.sign(username, JWT_SECRET, { expiresIn: "3600s" });
};

// listen for requests :)
const listener = app.listen(process.env.PORT, () => {
  console.log("Your app is listening on port " + listener.address().port);
});
