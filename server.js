require('dotenv').config(); // Load environment variables
const express = require('express');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const db = require('./db');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const socketIo = require('socket.io');
const http = require('http');
const forge = require('node-forge');
const fs = require('fs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

const otpStore = {};
const keysDir = path.join(__dirname, 'keys');
if (!fs.existsSync(keysDir)) {
    fs.mkdirSync(keysDir);
}

const transporter = nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

function generateOTP() {
    return crypto.randomInt(100000, 999999).toString();
}

function generateRSAKeys(username) {
    const keyPair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
    const publicKeyPem = forge.pki.publicKeyToPem(keyPair.publicKey);
    const privateKeyPem = forge.pki.privateKeyToPem(keyPair.privateKey);

    fs.writeFileSync(path.join(keysDir, `${username}_private.pem`), privateKeyPem);

    db.query('UPDATE users SET public_key = ? WHERE username = ?', [publicKeyPem, username], (err) => {
        if (err) console.error("Error storing public key in DB:", err);
    });
}


app.post('/signup', (req, res) => {
    const { email, username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);
    
    const query = 'INSERT INTO users (username, email, password, public_key) VALUES (?, ?, ?, ?)';
    db.query(query, [username, email, hashedPassword, ""], (err) => {
        if (err) {
            console.error(err);
            res.status(500).send('Error registering user');
        } else {
            generateRSAKeys(username);
            res.status(200).send('User registered successfully');
        }
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.query('SELECT email, password FROM users WHERE username = ?', [username], (err, result) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (result.length === 0) return res.status(404).json({ error: 'User not found' });

        const userEmail = result[0].email;
        const storedPassword = result[0].password;
        if (!bcrypt.compareSync(password, storedPassword)) {
            return res.status(401).json({ error: 'Incorrect password' });
        }

        const otp = generateOTP();
        const expiry = Date.now() + 5 * 60 * 1000;
        otpStore[userEmail] = { otp, expiry };

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: userEmail,
            subject: 'Your OTP Code',
            text: `Your OTP code is: ${otp}. It expires in 5 minutes.`
        };

        transporter.sendMail(mailOptions, (err) => {
            if (err) return res.status(500).json({ error: 'Failed to send OTP' });
            res.json({ message: 'OTP sent to your email', email: userEmail });
        });
    });
});

app.post('/verify-otp', (req, res) => {
    const { email, otp } = req.body;
    if (!otpStore[email]) return res.status(400).json({ error: 'No OTP found. Request a new one.' });
    const { otp: storedOtp, expiry } = otpStore[email];
    if (Date.now() > expiry) return res.status(400).json({ error: 'OTP expired. Request a new one.' });
    if (otp !== storedOtp) return res.status(400).json({ error: 'Invalid OTP' });
    delete otpStore[email];
    res.json({ message: 'Login successful!' });
});

app.get('/get-public-key', (req, res) => {
    const { receiver } = req.query;
    db.query('SELECT public_key FROM users WHERE username = ?', [receiver], (err, result) => {
        if (err || result.length === 0) return res.status(404).json({ error: 'Public key not found' });
        res.json({ publicKey: result[0].public_key });
    });
});

app.get('/get-private-key', (req, res) => {
    const { username } = req.query;
    const privateKeyPath = path.join(keysDir, `${username}_private.pem`);
    if (fs.existsSync(privateKeyPath)) {
        res.json({ privateKey: fs.readFileSync(privateKeyPath, 'utf8') });
    } else {
        res.status(404).json({ error: 'Private key not found' });
    }
});

app.post('/decrypt-message', (req, res) => {
    const { username } = req.query;
    const { messagePackage } = req.body;
    
    try {
        // Get the private key for this user
        const privateKeyPath = path.join(keysDir, `${username}_private.pem`);
        if (!fs.existsSync(privateKeyPath)) {
            return res.status(404).json({ error: 'Private key not found' });
        }
        
        const privateKeyPem = fs.readFileSync(privateKeyPath, 'utf8');
        const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
        
        // Decrypt the message
        const pkg = JSON.parse(messagePackage);
        
        // Decrypt the AES key with our private RSA key
        const decryptedKey = privateKey.decrypt(forge.util.decode64(pkg.encryptedKey));
        const iv = forge.util.decode64(pkg.iv);
        
        // Decrypt the message with the AES key
        const decipher = forge.cipher.createDecipher('AES-CBC', decryptedKey);
        decipher.start({iv: iv});
        decipher.update(forge.util.createBuffer(forge.util.decode64(pkg.encryptedMessage)));
        decipher.finish();
        const decryptedMessage = decipher.output.toString('utf8');
        
        res.json({ decryptedMessage });
    } catch (error) {
        console.error("Server-side decryption error:", error);
        res.status(500).json({ error: 'Failed to decrypt message' });
    }
});
io.on('connection', (socket) => {
    console.log('User connected:', socket.id);

    socket.on('sendMessage', ({ sender, receiver, messagePackage }) => {
        // Parse and log the message package details
        try {
            const msgPackage = JSON.parse(messagePackage);
            console.log(`\n=== Encrypted Message Details (${sender} → ${receiver}) ===`);
            console.log(`IV (Base64): ${msgPackage.iv.substring(0, 20)}...`);
            console.log(`Encrypted AES Key (Base64): ${msgPackage.encryptedKey.substring(0, 20)}...`);
            console.log(`Encrypted Message (Base64): ${msgPackage.encryptedMessage.substring(0, 20)}...`);
            console.log(`Total package size: ${messagePackage.length} bytes`);
            console.log(`============================================\n`);
        } catch (error) {
            console.error("Error logging message package:", error);
        }
        
        // Forward the message
        io.emit(`receiveMessage-${receiver}`, { sender, messagePackage });
    });

    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
    });
});

server.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});