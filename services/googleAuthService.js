const axios = require('axios');
const querystring = require('querystring');
const { OAuth2Client } = require('google-auth-library');

// Create an instance of OAuth2Client
const oauth2Client = new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.REDIRECT_URI
);

async function exchangeGoogleCodeForTokensAndProfile(code) {
    console.log({
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: process.env.REDIRECT_URI,
        grant_type: 'authorization_code',
    });
    
    const params = querystring.stringify({
        code: code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: process.env.REDIRECT_URI,
        grant_type: 'authorization_code'
    });

    try {
        const response = await axios.post('https://oauth2.googleapis.com/token', params, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
        });

        const tokens = response.data;
        
        // Get user profile using the ID token
        const ticket = await oauth2Client.verifyIdToken({
            idToken: tokens.id_token, // Ensure tokens.id_token exists
            audience: process.env.GOOGLE_CLIENT_ID,
        });
        const profile = ticket.getPayload();

        return { tokens, profile };
    } catch (error) {
        console.error('Error exchanging code for tokens:', error.response ? error.response.data : error.message);
        throw new Error('Failed to exchange code for tokens');
    }
}

module.exports = {
    exchangeGoogleCodeForTokensAndProfile,
};
