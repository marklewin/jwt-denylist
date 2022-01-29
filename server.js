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

  client.on("error", (error) => {
    console.log(error);
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
  if (token == null) {
    return response.status(403).send({
      message: "No token provided",
    });
  }

  // token in blacklist?
  const blacklisted = await client.get(`bl_${token}`);
  if (blacklisted) {
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
  });

  next();
};

app.post("/createUser", (request, response) => {
  const token = generateAccessToken({ username: request.body.username });
  response.json(token);
});

app.get("/", authenticateToken, (request, response) => {
  return response.status(200).send("Authentication successful");
});

app.post("/logout", authenticateToken, async (request, response) => {
  const { userId, token, tokenExp } = request;

  const token_key = `bl_${token}`;
  await client.set(token_key, token);
  client.expireAt(token_key, tokenExp);

  return response.status(200).send("Token invalidated");
});

const generateAccessToken = (username) => {
  return jwt.sign(username, JWT_SECRET, { expiresIn: "3600s" });
};

// listen for requests :)
const listener = app.listen(3000, () => {
  console.log("Server running");
});
