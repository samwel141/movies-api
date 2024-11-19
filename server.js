
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const cors = require('cors');
const axios = require('axios');
const dotenv = require('dotenv');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const { exchangeGoogleCodeForTokensAndProfile } = require('./services/googleAuthService');
const User = require('./models/User'); 

dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;
const apiKey = '0473ddfa4f94ee3962ec107595f0abd4';

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.options('*', cors());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

app.use(passport.initialize());
app.use(passport.session());

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
    useUnifiedTopology: true,
})
    .then(() => console.log('Connected to MongoDB'))
    .catch((err) => console.error('MongoDB connection error:', err));


app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

const SECRET_KEY = process.env.SECRET_KEY;
const REFRESH_SECRET_KEY = process.env.REFRESH_SECRET_KEY;
const TMDB_API_KEY = process.env.TMDB_API_KEY;

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "https://movies-app-tau-teal.vercel.app/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ email: profile.emails[0].value });

        if (!user) {
            user = new User({
                username: profile.displayName,
                email: profile.emails[0].value,
                watch_list: [],
                favorites: [],
                genres: [],
            });
            await user.save();
        }

        done(null, user);
    } catch (error) {
        done(error, null);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (error) {
        done(error, null);
    }
});

app.get('/', (req, res) => {
    res.send('Welcome to the Movies Application! Explore and enjoy your favorite movies.');
});

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.post('/auth/google/callback', async (req, res) => {
    const { code } = req.body;

    try {
        const { tokens, profile } = await exchangeGoogleCodeForTokensAndProfile(code);

        let user = await User.findOne({ email: profile.email });

        if (!user) {
            user = new User({
                username: profile.displayName,
                email: profile.email,
                googleId: profile.id
            });
            await user.save();
        }

        const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
        const refreshToken = jwt.sign({ id: user.id, username: user.username }, REFRESH_SECRET_KEY, { expiresIn: '7d' });

        res.json({
            message: 'Login successful',
            token,
            refreshToken,
            user
        });
    } catch (error) {
        console.error('Error during Google login:', error);
        res.status(500).json({ message: 'Login failed' });
    }
});

async function getTrailerForMovie(movieId) {
    try {
        const response = await axios.get(`https://api.themoviedb.org/3/movie/${movieId}/videos?api_key=${apiKey}&language=en-US`, {
            timeout: 20000 
        });
        const videos = response.data.results;
        const trailer = videos.find(video => video.type === 'Trailer' && video.site === 'YouTube');

        return trailer ? `https://www.youtube.com/watch?v=${trailer.key}` : null;
    } catch (error) {
        console.error(`Error fetching trailer for movie ID ${movieId}:`, error);
        return null;
    }
}

app.get('/movies', async (req, res) => {
    const { query, genre, year, rating, sort_by = 'popularity.desc', page = 1 } = req.query;

    try {
        let url = `https://api.themoviedb.org/3/discover/movie?api_key=${apiKey}&language=en-US&page=${page}&sort_by=${sort_by}`;

        if (query) {
            url = `https://api.themoviedb.org/3/search/movie?api_key=${apiKey}&language=en-US&page=${page}&query=${encodeURIComponent(query)}`;
        }

        if (genre) {
            url += `&with_genres=${genre}`;
        }

        if (year) {
            url += `&primary_release_year=${year}`;
        }

        if (rating) {
            url += `&vote_average.gte=${rating}`;
        }

        const response = await axios.get(url, {
            timeout: 20000 
        });
        const movies = response.data.results;
        const totalPages = response.data.total_pages;

        const moviesWithTrailers = await Promise.all(
            movies.map(async movie => ({
                ...movie,
                trailer: await getTrailerForMovie(movie.id),
            }))
        );

        res.json({ movies: moviesWithTrailers, totalPages });
    } catch (error) {
        console.error('Error fetching movies:', error);
        res.status(500).json({ message: 'Error fetching movies', error });
    }
});


app.get('/genres', async (req, res) => {
    try {
        const url = `https://api.themoviedb.org/3/genre/movie/list?api_key=0473ddfa4f94ee3962ec107595f0abd4&language=en-US`;
        const response = await axios.get(url, {
            timeout: 20000 
        });
        const genres = response.data.genres;

        res.json({ genres });
    } catch (error) {
        console.error('Error fetching genres:', error);
        res.status(500).json({ message: 'Error fetching genres' });
    }
});

app.get('/movies/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const url = `https://api.themoviedb.org/3/movie/${id}?api_key=${apiKey}&language=en-US`;
        const response = await axios.get(url, {
            timeout: 20000 
        });
        const movie = response.data;

        movie.trailer = await getTrailerForMovie(movie.id);

        res.json(movie);
    } catch (error) {
        console.error(`Error fetching movie with ID ${id}:`, error);
        res.status(500).json({ message: 'Error fetching movie' });
    }
});


app.get('/user/:id/lists', async (req, res) => {
    const { id } = req.params;
  
    try {
      const user = await User.findById(id);
  
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      res.json({
        watch_list: user.watch_list,
        favorites: user.favorites,
        genres: user.genres,
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Server error' });
    }
  });
  


app.post('/user/:id/watchlist', async (req, res) => {
    const { id } = req.params;
    const { movieId } = req.body;

    try {
        const user = await User.findById(id);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        if (!user.watch_list.includes(movieId)) {
            user.watch_list.push(movieId);
            await user.save();
        }

        res.json({ message: 'Movie added to watchlist', watch_list: user.watch_list });
    } catch (error) {
        res.status(500).json({ message: 'Error updating watchlist' });
    }
});

app.post('/user/:id/favorites', async (req, res) => {
    const { id } = req.params;
    const { movieId } = req.body;

    try {
        const user = await User.findById(id);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        if (!user.favorites.includes(movieId)) {
            user.favorites.push(movieId);
            await user.save();
        }

        res.json({ message: 'Movie added to favorites', favorites: user.favorites });
    } catch (error) {
        res.status(500).json({ message: 'Error updating favorites' });
    }
});


app.post('/user/:id/genres', async (req, res) => {
    const { id } = req.params;
    const { genreId } = req.body;
  
    try {
      const user = await User.findById(id);
  
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      if (!user.genres.includes(genreId)) {
        user.genres.push(genreId);  
        await user.save();
      }
  
      res.json({ message: 'Genre added to watched genres', genres: user.genres });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Server error' });
    }
  });
  



app.delete('/user/:id/watchlist', async (req, res) => {
    const { id } = req.params;
    const { movieId } = req.body;
  
    try {
      const user = await User.findById(id);
  
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      const movieIndex = user.watch_list.indexOf(movieId);
      if (movieIndex === -1) {
        return res.status(400).json({ message: 'Movie not in watchlist' });
      }
  
      user.watch_list.splice(movieIndex, 1);
      await user.save(); 
  
      res.json({ message: 'Movie removed from watchlist', watch_list: user.watch_list });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Server error' });
    }
  });


  app.delete('/user/:id/favorites', async (req, res) => {
    const { id } = req.params;
    const { movieId } = req.body;
  
    try {
      const user = await User.findById(id);
  
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      const movieIndex = user.favorites.indexOf(movieId);
      if (movieIndex === -1) {
        return res.status(400).json({ message: 'Movie not in favorites' });
      }
  
      user.favorites.splice(movieIndex, 1);
      await user.save();
  
      res.json({ message: 'Movie removed from favorites', favorites: user.favorites });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Server error' });
    }
  });

  app.delete('/user/:id/genres', async (req, res) => {
    const { id } = req.params;
    const { genreId } = req.body;
  
    try {
      const user = await User.findById(id);
  
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      const genreIndex = user.genres.indexOf(genreId);
      if (genreIndex === -1) {
        return res.status(400).json({ message: 'Genre not in user genres' });
      }
  
      user.genres.splice(genreIndex, 1);
      await user.save(); 
  
      res.json({ message: 'Genre removed from user genres', genres: user.genres });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Server error' });
    }
  });







  app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;

    try {
        const existingUser = await User.findOne({ username });
        const existingEmail = await User.findOne({ email });

        if (existingUser) {
            return res.status(400).json({ message: 'Username already exists' });
        }

        if (existingEmail) {
            return res.status(400).json({ message: 'Email already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        console.log(hashedPassword);

        const newUser = new User({
            username,
            email,
            password: hashedPassword,
        });

        await newUser.save();

        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});


app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    console.log(email);
    console.log(password);

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ message: 'Invalid Email' });
        }
        console.log(user);

        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Invalid Password' });
        }

        const token = jwt.sign({ id: user._id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
        const refreshToken = jwt.sign({ id: user._id, username: user.username }, REFRESH_SECRET_KEY, { expiresIn: '7d' });

        user.refreshToken = refreshToken;
        await user.save();

        res.json({ message: 'Login successful', token, refreshToken, user });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});



// app.get('/profile', async (req, res) => {
//     const token = req.headers.authorization.split(" ")[1];

//     if (!token) {
//         return res.status(401).json({ message: 'Unauthorized' });
//     }

//     try {
//         const decoded = jwt.verify(token, SECRET_KEY);
//         console.log(decoded);
//         const user = await User.findById(decoded._id);

//         if (!user) {
//             return res.status(404).json({ message: 'User not found' });
//         }

//         res.json({ message: 'User profile', user });
//     } catch (error) {
//         console.error(error);
//         res.status(401).json({ message: 'Invalid token' });
//     }
// });

app.post('/refresh-token', async (req, res) => {
    const { refreshToken } = req.body;
  
    if (!refreshToken) {
      return res.status(400).json({ message: 'No refresh token provided' });
    }
  
    try {
      const decoded = jwt.verify(refreshToken, REFRESH_SECRET_KEY);
      
      const user = await User.findById(decoded.id);
      if (!user || user.refreshToken !== refreshToken) {
        return res.status(403).json({ message: 'Invalid refresh token' });
      }
  
      const newToken = jwt.sign({ id: user._id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
  
      res.json({ token: newToken, user });
    } catch (error) {
      console.error('Error refreshing token:', error);
      res.status(403).json({ message: 'Invalid refresh token' });
    }
  });
  





app.put('/user/:id', async (req, res) => {
    const { id } = req.params;
    const { username, email, password } = req.body;

    try {
        let user = await User.findById(id);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        if (email) {
            const existingEmail = await User.findOne({ email });
            if (existingEmail && existingEmail.id !== id) {
                return res.status(400).json({ message: 'Email already in use' });
            }
            user.email = email;
        }

        if (username) user.username = username;
        if (password) user.password = await bcrypt.hash(password, 10);

        await user.save();

        res.json({ message: 'User updated', user });
    } catch (error) {
        res.status(500).json({ message: 'Error updating user' });
    }
});

app.get('/profile', async (req, res) => {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized: No token provided' });
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY);

        const user = await User.findById(decoded.id);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json({ message: 'User profile', user });
    } catch (error) {
        console.error(error);

        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Token expired' });
        } else if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Invalid token' });
        } else {
            return res.status(500).json({ message: 'Internal server error' });
        }
    }
});

