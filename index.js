const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// Endpoint to verify JWT value
app.post('/verifyToken', (req, res) => {
    const { token, key, period } = req.body;

    // Check if all fields are provided
    if (!token || !key || period === undefined) {
        return res.status(400).json({ error: 'Token, key, and period are required' });
    }

    try {
        // Decode the JWT without verifying the signature
        const decoded = jwt.decode(token);

        // If the key doesn't exist in the decoded JWT
        if (!decoded || decoded[key] === undefined) {
            return res.status(404).json({ error: `Key "${key}" not found in token` });
        }

        // Ensure the period is a valid number, regardless of its input type
        const periodValue = parseFloat(period);
        if (isNaN(periodValue)) {
            return res.status(400).json({ error: 'Invalid period value. Must be a valid number.' });
        }

        // Check if decoded[key] is a number (i.e., a timestamp)
        const keyValue = parseFloat(decoded[key]);
        if (isNaN(keyValue)) {
            return res.status(400).json({ error: `Value for key "${key}" in token is not a valid number.` });
        }

        // Current time in seconds
        const now = Math.floor(Date.now() / 1000);

        // Compare the key's value with the current time + period
        const comparisonValue = now + periodValue;
        if (keyValue > comparisonValue) {
            return res.json({ result: 'GREATER' });
        } else if (keyValue === comparisonValue) {
            return res.json({ result: 'EQUAL' });
        } else {
            return res.json({ result: 'LESSER' });
        }
    } catch (err) {
        return res.status(400).json({ error: 'Invalid token' });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'UP' });
});

app.get('/', (req, res) => {
    res.status(200).json({ status: 'UP' });
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
