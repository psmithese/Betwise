
const express = require("express")
const mongoose = require("mongoose")
const dotenv = require("dotenv")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const User = require("./userModel")
const Game = require("./gameModel")

dotenv.config()

const app = express()
app.use(express.json())

const PORT = process.env.PORT || 8000

mongoose.connect(process.env.MONGODB_URL)
.then(()=>{
    console.log("MongoDB connected...")
    app.listen(PORT, ()=>{
        console.log(`Server started running on Port ${PORT}`)
    }) 
})


const authenticate = (req, res, next) => {
  const token = req.header('Authorization');
  
  if (!token) {
    return res.status(401).json({ message: "No token, authorization denied" });
  }

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: "Token is not valid or has expired" });
  }
};


const adminOnly = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ message: "Access denied. Admin only." });
  }
};


app.post("/sign-up", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    if(!email) {
      return res.status(400).json({message: "Please add your email"});
    }
    
    if(!username) {
      return res.status(400).json({message: "Please enter a username"});
    }

    if(!password) {
      return res.status(400).json({message: "Please enter password"});
    }

    
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });

    if(existingUser) {
      return res.status(400).json({message: "User account already exists"});
    }

    if(password.length < 6) {
      return res.status(400).json({message: "Password should be a min of 6 chars"});
    }
    
    const hashedPassword = await bcrypt.hash(password, 12);

    const newUser = new User({ 
      username,
      email, 
      password: hashedPassword,
      walletBalance: 100 
    });

    await newUser.save();

    res.status(201).json({
      message: "User account created successfully",
      user: { 
        username: newUser.username,
        email: newUser.email,
        walletBalance: newUser.walletBalance,
        role: newUser.role
      }
    });
  } catch (error) {
    res.status(500).json({message: error.message});
  }
});


app.post("/admin-signup", async (req, res) => {
  try {
    const { username, email, password, adminSecret } = req.body;
    
    
    if (!adminSecret || adminSecret !== process.env.ADMIN_SECRET) {
      return res.status(403).json({message: "Invalid admin credentials"});
    }
    
    if(!email || !username || !password) {
      return res.status(400).json({message: "All fields are required"});
    }

    
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });

    if(existingUser) {
      return res.status(400).json({message: "User account already exists"});
    }

    if(password.length < 6) {
      return res.status(400).json({message: "Password should be a min of 6 chars"});
    }
    
    const hashedPassword = await bcrypt.hash(password, 12);

    const newAdmin = new User({ 
      username,
      email, 
      password: hashedPassword,
      role: 'admin', 
      walletBalance: 100
    });

    await newAdmin.save();

    res.status(201).json({
      message: "Admin account created successfully",
      user: { 
        username: newAdmin.username,
        email: newAdmin.email,
        role: newAdmin.role,
        walletBalance: newAdmin.walletBalance
      }
    });
  } catch (error) {
    res.status(500).json({message: error.message});
  }
});


app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const user = await User.findOne({ username });
    
    if(!user) {
      return res.status(404).json({message: "User account does not exist."});
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    
    if(!isMatch) {
      return res.status(400).json({message: "Incorrect username or password."});
    }
    
    
    const accessToken = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      process.env.ACCESS_TOKEN,
      { expiresIn: "5m" }
    );
    
    const refreshToken = jwt.sign(
      { id: user._id },
      process.env.REFRESH_TOKEN,
      { expiresIn: "30d" }
    );
    
    res.status(200).json({
      message: "Login successful",
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        walletBalance: user.walletBalance
      }
    });
  } catch (error) {
    res.status(500).json({message: error.message});
  }
});


app.post("/refresh-token", async (req, res) => {
  const { refreshToken } = req.body;
  
  if (!refreshToken) {
    return res.status(401).json({ message: "No refresh token provided" });
  }

  try {
    
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN);
    
    
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    
    
    const accessToken = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      process.env.ACCESS_TOKEN,
      { expiresIn: "5m" }
    );
    
    res.json({ accessToken });
  } catch (err) {
    console.error(err.message);
    res.status(401).json({ message: "Invalid refresh token" });
  }
});


app.get("/user/profile", authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({message: "Server error"});
  }
});


app.get("/user/check-admin", authenticate, async (req, res) => {
  try {
    const isAdmin = req.user.role === 'admin';
    res.json({ isAdmin });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({message: "Server error"});
  }
});


app.put("/user/wallet", authenticate, async (req, res) => {
  const { amount } = req.body;

  if (!amount || isNaN(amount) || amount <= 0) {
    return res.status(400).json({ message: "Please provide a valid amount" });
  }

  try {
    const user = await User.findById(req.user.id);
    user.walletBalance += Number(amount);
    await user.save();
    res.json({ walletBalance: user.walletBalance });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({message: "Server error"});
  }
});


app.post("/games", authenticate, adminOnly, async (req, res) => {
  const { title, description, teams, startTime } = req.body;

  try {
    const newGame = new Game({
      title,
      description,
      teams,
      startTime,
      createdBy: req.user.id
    });

    const game = await newGame.save();
    res.json(game);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({message: "Server error"});
  }
});


app.get("/games", async (req, res) => {
  try {
    const games = await Game.find().sort({ startTime: 1 });
    res.json(games);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({message: "Server error"});
  }
});


app.get("/games/upcoming", async (req, res) => {
  try {
    const games = await Game.find({ 
      startTime: { $gt: new Date() },
      status: 'upcoming'
    }).sort({ startTime: 1 });
    res.json(games);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({message: "Server error"});
  }
});


app.get("/games/:id", async (req, res) => {
  try {
    const game = await Game.findById(req.params.id);
    if (!game) {
      return res.status(404).json({ message: "Game not found" });
    }
    res.json(game);
  } catch (err) {
    console.error(err.message);
    if (err.kind === 'ObjectId') {
      return res.status(404).json({ message: "Game not found" });
    }
    res.status(500).json({message: "Server error"});
  }
});


app.put("/games/:id", authenticate, adminOnly, async (req, res) => {
  const { status, result } = req.body;

  try {
    let game = await Game.findById(req.params.id);
    if (!game) {
      return res.status(404).json({ message: "Game not found" });
    }

    
    if (status) game.status = status;
    if (result) game.result = result;
    
    
    if (status === 'completed' && !game.endTime) {
      game.endTime = new Date();
    }

    await game.save();
    res.json(game);
  } catch (err) {
    console.error(err.message);
    res.status(500).json({message: "Server error"});
  }
});


app.delete("/games/:id", authenticate, adminOnly, async (req, res) => {
  try {
    const game = await Game.findById(req.params.id);
    if (!game) {
      return res.status(404).json({ message: "Game not found" });
    }

    await Game.findByIdAndDelete(req.params.id);
    res.json({ message: "Game removed" });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({message: "Server error"});
  }
});