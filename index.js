import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
import { User } from "./models/User.js";
import connectToDb from "./database/db.js";
import "dotenv/config";

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.SECRET_KEY;

// Connect to MongoDB
connectToDb();

// Home route
app.get("/", (req, res) => {
  res.send("Welcome to the authentication API");
});

// Signup route
app.post("/api/signup", async (req, res) => {
  const { email, name, password } = req.body;
  if (!email || !name || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email, name, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: "User created successfully" });
  } catch (error) {
    res.status(400).json({ error: "Email already exists" });
  }
});

// Login route
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (user && (await bcrypt.compare(password, user.password))) {
    const token = jwt.sign({ userId: user._id }, SECRET_KEY, {
      expiresIn: "1h",
    });
    res.status(200).json({ message: "Login successful", token });
  } else {
    res.status(401).json({ error: "Invalid credentials" });
  }
});

// Protected route
app.get("/api/user", (req, res) => {
  const token = req.headers.authorization.split(" ")[1];
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(401).json({ error: "Unauthorized" });
    res.json(user);
  });
});

app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});
