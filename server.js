require('dotenv').config();
const express = require("express");
const http = require("http");
const cors = require("cors");
const { OAuth2Client } = require("google-auth-library");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json()); // To parse JSON body

app.use(express.static('public'));

// Google OAuth Configuration
const client = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET
);

// JWT Token Generation
const generateToken = (user) => {
  return jwt.sign(
    {
      email: user.email,
      name: user.name,
    },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
};

// Google OAuth Authentication Route
app.post("/dev/auth", async (req, res) => {
  const { code } = req.body; // Expecting an auth code from frontend
  if (!code)
    return res.status(400).json({ error: "Authorization code is missing" });

  try {
    // Exchange authorization code for tokens
    const { tokens } = await client.getToken({
      code,
      redirect_uri: "postmessage",
    });

    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    console.log("Google User Payload:", payload);

    const { email, name, picture } = payload;

    const user = {
      email,
      name,
      picture,
    };

    const token = generateToken(user);

    res.json({
      message: "User  authenticated successfully",
      user: {
        email: user.email,
        name: user.name,
        picture: user.picture,
      },
      token,
    });
  } catch (error) {
    console.error("Authentication Error:", error);
    res.status(401).json({ error: "Invalid or expired authorization code" });
  }
});

// Server Configuration
const port = process.env.PORT || 3000;
const server = http.createServer(app);

server.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
