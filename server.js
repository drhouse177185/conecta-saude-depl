// NOME DO ARQUIVO: server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { MercadoPagoConfig, Preference } = require('mercadopago');
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

// --- CONFIG ---
const app = express();
const port = process.env.PORT || 3000;

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Inicializa MP apenas se tiver token configurado
const mpToken = process.env.MP_ACCESS_TOKEN;
const client = mpToken ? new MercadoPagoConfig({ accessToken: mpToken }) : null;

app.use(cors());
app.use(express.json());

// --- MIDDLEWARE AUTH ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401).json({ error: "Token não fornecido" });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Token inválido" });
        req.user = user;
        next();
    });
};

// --- ROTAS ---

// Registro
app.post('/auth/register', async (req, res) => {
    const { name, email, password, cpf, age, sex } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await pool.query(
            "INSERT INTO users (name, email, password_hash, cpf, age, sex) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, email, role, credits",
            [name, email.toLowerCase().trim(), hashedPassword, cpf, age, sex]
        );
        res.json(newUser.rows[0]);
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: "Email ou CPF já cadastrados." });
        res.status(500).json({ error: "Erro interno no servidor." });
    }
});

// Login
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query("SELECT * FROM users WHERE email = $1", [email.toLowerCase().trim()]);
        if (result.rows.length === 0) return res.status(400).json({ error: "Usuário não encontrado." });

        const user = result.rows[0];
        if (await bcrypt.compare(password, user.password_hash)) {
            // Lógica de Recarga Automática SUS (Simplificada)
            const today = new Date();
            const last = new Date(user.last_recharge_date);
            const diffDays = Math.ceil(Math.abs(today - last) / (1000 * 60 * 60 * 24));
            let recharged = false;
            
            // Regra: > 60 anos (180 dias), <= 60 anos (365 dias)
            if ((user.age > 60 && diffDays >= 180) || (user.age <= 60 && diffDays >= 365)) {
                await pool.query("UPDATE users SET credits = 100, last_recharge_date = CURRENT_DATE WHERE id = $1", [user.id]);
                user.credits = 100;
                recharged = true;
            }

            const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '24h' });
            res.json({ token, user: { ...user, password_hash: undefined, recharged_message: recharged ? "Sua cota SUS foi renovada!" : null } });
        } else {
            res.status(403).json({ error: "Senha incorreta." });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Erro interno." });
    }
});

// IA Segura
app.post('/ai/generate', authenticateToken, async (req, res) => {
    const { prompt, cost, isJson } = req.body;
    
    // Verificar Créditos
    const userRes = await pool.query("SELECT credits FROM users WHERE id = $1", [req.user.id]);
    if (userRes.rows[0].credits < cost) return res.status(402).json({ error: "Créditos insuficientes." });

    try {
        const apiKey = process.env.GEMINI_API_KEY;
        const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key=${apiKey}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ contents: [{ parts: [{ text: isJson ? prompt + "\nResponda APENAS JSON." : prompt }] }] })
        });
        
        const data = await response.json();
        const txt = data.candidates?.[0]?.content?.parts?.[0]?.text;
        
        if (!txt) throw new Error("IA não retornou texto.");

        let finalResult = txt;
        if (isJson) {
            try {
                finalResult = JSON.parse(txt.replace(/```json/g, '').replace(/```/g, '').trim());
            } catch (e) {
                console.error("Erro JSON parse IA", e);
                // Retorna texto puro em caso de falha no JSON para não quebrar
            }
        }

        // Debitar
        const clientDb = await pool.connect();
        try {
            await clientDb.query('BEGIN');
            await clientDb.query("UPDATE users SET credits = credits - $1 WHERE id = $2", [cost, req.user.id]);
            await clientDb.query("INSERT INTO transactions (user_id, amount, description, type) VALUES ($1, $2, $3, 'usage')", [req.user.id, -cost, 'Uso IA']);
            await clientDb.query('COMMIT');
            
            res.json({ result: finalResult, new_credits: userRes.rows[0].credits - cost });
        } catch (e) {
            await clientDb.query('ROLLBACK');
            throw e;
        } finally {
            clientDb.release();
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Erro ao processar IA." });
    }
});

// Pagamento
app.post('/create_preference', authenticateToken, async (req, res) => {
    if (!client) return res.status(500).json({ error: "Mercado Pago não configurado no servidor." });
    
    try {
        const { description, price, quantity, creditsToAdd } = req.body;
        const preference = new Preference(client);
        const result = await preference.create({
            body: {
                items: [{ title: description, unit_price: Number(price), currency_id: "BRL", quantity: Number(quantity) }],
                back_urls: { success: "https://seusite.com/success", failure: "https://seusite.com/fail", pending: "https://seusite.com/pending" },
                auto_return: "approved",
                metadata: { user_id: req.user.id, credits_to_add: creditsToAdd }
            }
        });
        res.json({ id: result.id });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Erro MP" });
    }
});

// Recuperar por CPF
app.post('/auth/recover-cpf', async (req, res) => {
    const { cpf } = req.body;
    try {
        const result = await pool.query("SELECT email FROM users WHERE cpf = $1", [cpf]);
        if (result.rows.length > 0) {
            res.json({ found: true, message: `Conta encontrada! Link enviado para ${result.rows[0].email} (Simulado)` });
        } else {
            res.status(404).json({ error: "CPF não encontrado." });
        }
    } catch (err) {
        res.status(500).json({ error: "Erro interno." });
    }
});

app.get('/', (req, res) => res.send("API Conecta Saúde Online"));

app.listen(port, () => console.log(`Server running on port ${port}`));