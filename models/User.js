const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    googleId: { type: String },
    watch_list: [{ type: String }],
    favorites: [{ type: String }],  
    genres: [{ type: String }]      
});

const User = mongoose.model('User', userSchema);

module.exports = User;
