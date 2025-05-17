const mongoose = require("mongoose");

const gameSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true, 
    trim: true 
  },
  description: { 
    type: String, 
    required: true 
  },
  teams: [{
    name: {
      type: String, 
      required: true
    },
    odds: {
      type: Number,
      required: true,
      min: 1.01 
    }
  }],
  startTime: {
    type: Date,
    required: true 
  },
  endTime: { 
    type: Date 
  },
  status: { 
    type: String, 
    enum: ['upcoming', 'active', 'completed', 'cancelled'],
    default: 'upcoming'
  },
  result: { 
    winningTeam: {
      type: String 
    },
    finalScore: {
      type: String
    }
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User',
    required: true 
  }
}, {timestamps: true});

const Game = mongoose.model("Game", gameSchema);

module.exports = Game;