const crypto = require("crypto");
require("dotenv").config({ path: "./.env" });
const ENCRYPTION_SECRET_KEY = process.env.ENCRYPTION_SECRET_KEY;
const IV_LENGTH = 16;
const jwt = require("jsonwebtoken");


function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const key = crypto.createHash("sha256").update(ENCRYPTION_SECRET_KEY).digest();
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  const encrypted = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  return iv.toString("hex") + ":" + encrypted.toString("hex");
}

function decrypt(encryptedText) {
  const [ivHex, encryptedHex] = encryptedText.split(":");
  const iv = Buffer.from(ivHex, "hex");
  const encrypted = Buffer.from(encryptedHex, "hex");
  const key = crypto.createHash("sha256").update(ENCRYPTION_SECRET_KEY).digest();
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString("utf8");
}


require("dotenv").config({ path: "./.env" });

const admin = require("firebase-admin");
const serviceAccount = JSON.parse(
  Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT, "base64").toString("utf8")
);
const { log } = require("./logger");

// Initialisation Firebase
try {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
  log("✅ Firebase initialisé avec succès");
} catch (error) {
  log(`❌ Erreur initialisation Firebase: ${error.message}`);
  process.exit(1);
}

const express = require("express");
const cors = require("cors");

const http = require("http");
const { Server } = require("socket.io");
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const { v4: uuidv4 } = require("uuid");
const sqlite3 = require("sqlite3").verbose();
const bitcoin = require("bitcoinjs-lib");
const axios = require("axios");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");

const app = express();

// Middlewares de sécurité
app.use(helmet());
const allowedOrigins = [
  'https://birkov-extract.vercel.app',
  'http://localhost:5173'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('CORS not allowed'));
  },
  credentials: true
}));

app.use(express.json({ limit: "10kb" }));

// Configuration Bitcoin
const BTC_NETWORK = process.env.BTC_NETWORK === "mainnet" 
  ? bitcoin.networks.bitcoin 
  : bitcoin.networks.testnet;

const BLOCKCHAIN_API = process.env.BTC_NETWORK === "mainnet"
  ? "https://blockstream.info/api"
  : "https://blockstream.info/testnet/api";

// Initialisation base de données SQLite
const db = new sqlite3.Database("./payments.db", sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
  if (err) {
    log(`❌ Erreur connexion SQLite: ${err.message}`);
    process.exit(1);
  }
  log("✅ Connecté à la base de données SQLite");

  // Création des tables si elles n'existent pas
  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS invoices (
      id TEXT PRIMARY KEY,
      address TEXT NOT NULL,
      amount REAL NOT NULL,
      currency TEXT DEFAULT 'BTC',
      status TEXT DEFAULT 'pending',
      user_id TEXT NOT NULL,
      plan TEXT NOT NULL,
      duration INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      confirmed_at DATETIME,
      tx_hash TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      premium_expiry DATETIME,
      plan TEXT DEFAULT 'free'
    )`);
  });
});

// Configuration du serveur HTTP et WebSocket
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    methods: ['GET', 'POST'],
    credentials: true
  },
  connectionStateRecovery: {
    maxDisconnectionDuration: 2 * 60 * 1000,
    skipMiddlewares: true
  }
});


// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true
});
app.use("/api/", apiLimiter);

// Middleware de validation d'adresse Bitcoin
const validateBitcoinAddress = (req, res, next) => {
  const { address } = req.body;
  if (!address) {
    return res.status(400).json({ error: "Adresse Bitcoin manquante" });
  }

  try {
    bitcoin.address.toOutputScript(address, BTC_NETWORK);
    next();
  } catch (err) {
    log(`❌ Adresse Bitcoin invalide: ${address} | Erreur: ${err.message}`);
    res.status(400).json({ error: "Adresse Bitcoin invalide" });
  }
};
async function ensureUserInSQLite(uid) {
  return new Promise((resolve, reject) => {
    db.get("SELECT id FROM users WHERE id = ?", [uid], async (err, row) => {
      if (err) return reject(err);
      if (row) return resolve(true); // Déjà présent

      try {
        const userRecord = await admin.auth().getUser(uid);
        const email = userRecord.email || `${uid}@unknown.email`;

        db.run(
          "INSERT INTO users (id, email, plan) VALUES (?, ?, 'free')",
          [uid, email],
          (err) => {
            if (err) return reject(err);
            log(`✅ Utilisateur ${uid} ajouté à SQLite avec email ${email}`);
            resolve(true);
          }
        );
      } catch (firebaseError) {
        log(`❌ Firebase: utilisateur ${uid} introuvable`);
        reject(firebaseError);
      }
    });
  });
}


// Middleware de gestion d'erreurs global
app.use((err, req, res, next) => {
  log(`💥 Erreur non capturée: ${err.stack}`);
  res.status(500).json({ 
    error: "Erreur interne du serveur",
    details: process.env.NODE_ENV === "development" ? err.message : undefined
  });
});

app.post("/api/init-user", async (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: "userId requis" });

  try {
    await ensureUserInSQLite(userId);
    res.json({ success: true });
  } catch (err) {
    log(`❌ Erreur init-user : ${err.message}`);
    res.status(500).json({ error: "Erreur init-user" });
  }
});

/**
 * Routes API
 */

// Route pour login admin
app.post("/api/admin-login", (req, res) => {
  const { email, password } = req.body;

  if (
    email === process.env.ADMIN_EMAIL &&
    password === process.env.ADMIN_PASSWORD
  ) {
    const token = jwt.sign({ role: "admin" }, process.env.ADMIN_TOKEN_SECRET, {
      expiresIn: "1h",
    });
    return res.json({ success: true, token });
  }

  res.status(401).json({ success: false, message: "Identifiants incorrects" });
});

// Middleware pour sécuriser routes admin
function verifyAdminToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) return res.status(401).json({ error: "Token manquant" });

  try {
    const decoded = jwt.verify(token, process.env.ADMIN_TOKEN_SECRET);
    if (decoded.role === "admin") return next();
    res.status(403).json({ error: "Accès refusé" });
  } catch (err) {
    res.status(401).json({ error: "Token invalide" });
  }
}

// Exemple de route protégée (ajoute où tu veux)
app.get("/api/protected-admin-data", verifyAdminToken, (req, res) => {
  res.json({ message: "Données sensibles visibles uniquement par l’admin." });
});

// Récupération du plan utilisateur
app.get("/api/user-plan/:uid", async (req, res) => {
  const uid = req.params.uid;
  if (!uid) return res.status(400).json({ error: "uid manquant" });

  try {
    await ensureUserInSQLite(uid);
    db.get("SELECT plan FROM users WHERE id = ?", [uid], (err, row) => {
      if (err) {
        log(`❌ SQLite read: ${err.message}`);
        return res.status(500).json({ error: "Erreur BD" });
      }
      return res.json({ plan: row?.plan || "free" });
    });
  } catch (error) {
    log(`❌ Erreur user-plan: ${error.message}`);
    res.status(500).json({ error: "Erreur serveur" });
  }
});


// Enregistrement utilisateur
app.post("/api/register-user", async (req, res) => {
  try {
    const { id, email, plan = "free" } = req.body;
    
    if (!id || !email) {
      return res.status(400).json({ error: "ID et email requis" });
    }

    await new Promise((resolve, reject) => {
      db.run(
        "INSERT OR REPLACE INTO users (id, email, plan) VALUES (?, ?, ?)",
        [id, email, plan],
        (err) => err ? reject(err) : resolve()
      );
    });

    log(`📝 Utilisateur enregistré: ${email} (${id})`);
    res.json({ success: true });
  } catch (error) {
    log(`❌ Erreur register-user: ${error.message}`);
    res.status(500).json({ error: "Erreur enregistrement" });
  }
});


// Génération d'adresse de paiement
app.post("/api/generate-address", async (req, res) => {
  try {
    const { userId, plan, duration } = req.body;

    if (!userId || !["Basique", "Pro", "Illimité"].includes(plan) || ![1, 3, 6, 12].includes(parseInt(duration))) {
      return res.status(400).json({ error: "Paramètres invalides" });
    }

    // Vérifier si l'utilisateur existe dans SQLite, sinon récupérer depuis Firebase
    const userFromDB = await new Promise((resolve, reject) => {
      db.get("SELECT email FROM users WHERE id = ?", [userId], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    let email = userFromDB?.email || null;

    if (!email) {
      // Récupération depuis Firebase Auth
      const firebaseUser = await admin.auth().getUser(userId);
      email = firebaseUser.email || `${userId}@unknown.email`;

      // Mise à jour SQLite
      await new Promise((resolve, reject) => {
        db.run(
          `INSERT OR REPLACE INTO users (id, email, plan) VALUES (?, ?, ?)`,
          [userId, email, "free"],
          (err) => (err ? reject(err) : resolve())
        );
      });
    }

    // Génération de la paire de clés BTC
    const keyPair = bitcoin.ECPair.makeRandom({ network: BTC_NETWORK });
    const privateKeyWIF = keyPair.toWIF();
    const { address } = bitcoin.payments.p2wpkh({
      pubkey: keyPair.publicKey,
      network: BTC_NETWORK,
    });

    const invoiceId = uuidv4();
    
    // Nouveaux montants avec durées
    const amounts = {
      Basique: {
        1: 0.00029,   // 1 month
        3: 0.00029 * 3 * 0.9,   // 3 months with 10% discount
        6: 0.00029 * 6 * 0.8,   // 6 months with 20% discount
        12: 0.00029 * 12 * 0.7  // 12 months with 30% discount
      },
      Pro: {
        1: 0.00079,
        3: 0.00079 * 3 * 0.9,
        6: 0.00079 * 6 * 0.8,
        12: 0.00079 * 12 * 0.7
      },
      Illimité: {
        1: 0.00149,
        3: 0.00149 * 3 * 0.9,
        6: 0.00149 * 6 * 0.8,
        12: 0.00149 * 12 * 0.7
      }
    };
    
    const amount = amounts[plan]?.[duration];
    if (amount === undefined) {
      log(`❌ Montant non trouvé pour plan: ${plan}, durée: ${duration}`);
      return res.status(400).json({ error: "Configuration de prix invalide" });
    }

    // Enregistrement dans SQLite
    await new Promise((resolve, reject) => {
      db.run(
        `INSERT INTO invoices (id, address, amount, user_id, plan, duration) VALUES (?, ?, ?, ?, ?, ?)`,
        [invoiceId, address, amount, userId, plan, duration],
        (err) => (err ? reject(err) : resolve())
      );
    });

    // Stockage dans Firestore
    const firestore = admin.firestore();

    // Sauvegarde dans BTC_KEYS
    await firestore.collection("BTC_KEYS").doc(invoiceId).set({
      userId,
      email,
      invoiceId,
      address,
      privateKey: encrypt(privateKeyWIF),
      plan,
      duration,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    log(`📬 Adresse BTC générée pour ${userId} (${email}) [${plan} - ${duration} mois] → ${address} | ${amount} BTC`);

    res.json({
      success: true,
      address,
      invoiceId,
      amount,
      amountSatoshis: amount * 1e8,
      duration
    });
  } catch (error) {
    log(`❌ Erreur generate-address: ${error.message}`);
    res.status(500).json({ error: "Erreur de génération" });
  }
});


// Récupération de la facture en attente
app.get("/api/pending-invoice/:uid", async (req, res) => {
  try {
    const userId = req.params.uid;
    if (!userId) {
      return res.status(400).json({ error: "ID utilisateur manquant" });
    }

    const invoice = await new Promise((resolve, reject) => {
      db.get(
        `SELECT * FROM invoices 
         WHERE user_id = ? AND status = 'pending' 
         ORDER BY created_at DESC LIMIT 1`,
        [userId],
        (err, row) => err ? reject(err) : resolve(row)
      );
    });

    if (!invoice) {
      return res.status(404).json({ error: "Aucune facture en attente" });
    }

    res.json(invoice);
  } catch (error) {
    log(`❌ Erreur pending-invoice: ${error.message}`);
    res.status(500).json({ error: "Erreur serveur" });
  }
});

// Vérification de paiement
app.post("/api/verify-payment", validateBitcoinAddress, async (req, res) => {
  try {
    const { address, invoiceId } = req.body;
    
    if (!invoiceId) {
      return res.status(400).json({ error: "ID de facture manquant" });
    }

    // Récupération de la facture
    const invoice = await new Promise((resolve, reject) => {
      db.get(
        `SELECT amount, user_id, plan FROM invoices 
         WHERE id = ? AND address = ?`, 
        [invoiceId, address], 
        (err, row) => err ? reject(err) : resolve(row)
      );
    });

    if (!invoice) {
      log(`❌ Facture introuvable: ${invoiceId} pour ${address}`);
      return res.status(404).json({ error: "Facture introuvable" });
    }

    // Vérification des transactions sur la blockchain
    const response = await axios.get(`${BLOCKCHAIN_API}/address/${address}/txs`, {
      timeout: 10000 // 10 secondes timeout
    });

    const transactions = Array.isArray(response.data) 
      ? response.data.filter(tx => tx.status?.confirmed)
      : [];

    log(`📦 ${transactions.length} transaction(s) confirmée(s) pour ${address}`);

    // Calcul du montant reçu
    let totalReceived = 0;
    const txHashes = [];
    
    transactions.forEach((tx) => {
      tx.vout.forEach((vout) => {
        if (vout.scriptpubkey_address?.toLowerCase() === address.toLowerCase()) {
          totalReceived += vout.value;
          if (tx.txid) txHashes.push(tx.txid);
        }
      });
    });

    const expectedSats = Math.round(invoice.amount * 1e8);
    const isPaid = totalReceived >= expectedSats;
    const receivedBTC = totalReceived / 1e8;

    log(`🔍 Paiement vérifié - Reçu: ${receivedBTC} BTC | Requis: ${invoice.amount} BTC`);

    if (isPaid && txHashes.length > 0) {
      await new Promise((resolve, reject) => {
        db.run(
          `UPDATE invoices SET status = 'paid', tx_hash = ?, confirmed_at = CURRENT_TIMESTAMP 
           WHERE id = ?`,
          [txHashes[0], invoiceId], 
          (err) => err ? reject(err) : resolve()
        );
      });
      
      log(`✅ Paiement confirmé pour ${invoiceId}`);
      await activatePremiumAccount(invoice.user_id, invoice.plan, invoiceId, receivedBTC, invoice.duration);
    }

    res.json({ 
      paid: isPaid, 
      amountReceived: receivedBTC, 
      amountExpected: invoice.amount,
      txHash: isPaid ? txHashes[0] : null
    });

  } catch (error) {
    log(`❌ Erreur verify-payment: ${error.message}`);
    
    if (error.response) {
      // Erreur de l'API blockchain
      res.status(502).json({ error: "Erreur de connexion au réseau Bitcoin" });
    } else if (error.request) {
      // Timeout ou pas de réponse
      res.status(504).json({ error: "Timeout de vérification" });
    } else {
      // Erreur interne
      res.status(500).json({ error: "Erreur de vérification" });
    }
  }
});

/**
 * Fonctions principales
 */

// Activation compte premium
async function activatePremiumAccount(userId, plan, invoiceId, receivedBTC, duration) {
  if (!userId || !plan || !invoiceId || typeof receivedBTC !== "number" || ![1, 3, 6, 12].includes(duration)) return;

  const expiryDate = new Date();
  expiryDate.setMonth(expiryDate.getMonth() + duration); // Ajoute la durée en mois

  try {
    const user = await new Promise((resolve, reject) => {
      db.get(`SELECT email FROM users WHERE id = ?`, [userId], (err, row) =>
        err ? reject(err) : resolve(row)
      );
    });

    if (!user) {
      log(`❌ Utilisateur introuvable: ${userId}`);
      return;
    }

    const firestore = admin.firestore();

    // 🔐 Récupération de la clé privée et de l'adresse depuis BTC_KEYS
    const keySnap = await firestore.collection("BTC_KEYS").doc(invoiceId).get();
    const keyData = keySnap.exists ? keySnap.data() : {};
    let privateKey = "NOT_FOUND";
    if (keyData.privateKey) {
      try {
        privateKey = decrypt(keyData.privateKey);
      } catch (e) {
        log(`❌ Erreur déchiffrement clé privée: ${e.message}`);
      }
    }

    const address = keyData.address || "UNKNOWN";

    // 🔄 Mise à jour locale SQLite
    await new Promise((resolve, reject) => {
      db.run(
        `INSERT OR REPLACE INTO users (id, email, premium_expiry, plan)
         VALUES (?, ?, ?, ?)`,
        [userId, user.email, expiryDate.toISOString(), plan],
        (err) => (err ? reject(err) : resolve())
      );
    });

    // 📢 WebSocket
    io.emit("payment-confirmed", { userId, plan, duration });

    // 🧾 Récupération de la transaction hash
    const invoiceData = await new Promise((resolve, reject) => {
      db.get(`SELECT tx_hash FROM invoices WHERE id = ?`, [invoiceId], (err, row) =>
        err ? reject(err) : resolve(row)
      );
    });
    const txHash = invoiceData?.tx_hash || null;

    // 📝 Firestore batch updates
    const batch = firestore.batch();

    // 1. Mise à jour du document utilisateur
    const userRef = firestore.collection("Users").doc(userId);
    batch.update(userRef, {
      plan,
      paymentsDate: admin.firestore.Timestamp.now(),
      subscriptionDate: expiryDate.toISOString(),
      durationMonths: duration
    });

    // 2. Ajout dans PAYMENTS
    const paymentRef = firestore.collection("PAYMENTS").doc();
    batch.set(paymentRef, {
      id: userId,
      email: user.email,
      invoice: invoiceId,
      plan,
      address,
      privateKey,
      txHash,
      amountReceived: receivedBTC,
      paidAt: admin.firestore.FieldValue.serverTimestamp(),
      premiumExpiry: admin.firestore.Timestamp.fromDate(expiryDate),
      btcClaimed : false,
      
    });

    // 3. Mise à jour de BTC_KEYS (ajout de paid et amount)
    const btcKeyRef = firestore.collection("BTC_KEYS").doc(invoiceId);
    batch.update(btcKeyRef, {
      paid: true,
      amount: receivedBTC,
      txHash: txHash || null,
    });

    // 4. Ajout dans KEYS (archive)
    const keyArchiveRef = firestore.collection("KEYS").doc(invoiceId);
    batch.set(keyArchiveRef, {
      userId,
      email: user.email,
      invoiceId,
      plan,
      address,
      privateKey,
      txHash,
      amount: receivedBTC,
      paidAt: admin.firestore.FieldValue.serverTimestamp(),
      expiryDate: admin.firestore.Timestamp.fromDate(expiryDate),
    });

    await batch.commit();

    log(`🔥 Firestore synchronisé pour ${userId} (PAIEMENT + BTC_KEYS + KEYS)`);

  } catch (error) {
    log(`❌ Erreur activatePremiumAccount: ${error.message}`);
  }
}




// Vérification périodique des paiements en attente
async function checkPendingPayments() {
  try {
    log("🔍 Début vérification des paiements en attente...");
    
    const invoices = await new Promise((resolve, reject) => {
      db.all("SELECT * FROM invoices WHERE status = 'pending'", (err, rows) => {
        err ? reject(err) : resolve(rows || []);
      });
    });

    log(`📋 ${invoices.length} facture(s) en attente à vérifier`);

    for (const invoice of invoices) {
      try {
        const response = await axios.get(`${BLOCKCHAIN_API}/address/${invoice.address}/txs`, {
          timeout: 15000
        });

        const transactions = Array.isArray(response.data) 
          ? response.data.filter(tx => tx.status?.confirmed)
          : [];

        let totalReceived = 0;
        const txHashes = [];
        
        transactions.forEach(tx => {
          tx.vout.forEach(v => {
            if (v.scriptpubkey_address === invoice.address) {
              totalReceived += v.value;
              if (tx.txid) txHashes.push(tx.txid);
            }
          });
        });

        const isPaid = totalReceived >= invoice.amount * 1e8;
        const receivedBTC = totalReceived / 1e8;

        if (isPaid && txHashes.length > 0) {
          await new Promise((resolve, reject) => {
            db.run(
              `UPDATE invoices SET status = 'paid', tx_hash = ?, confirmed_at = CURRENT_TIMESTAMP 
               WHERE id = ?`,
              [txHashes[0], invoice.id], 
              (err) => err ? reject(err) : resolve()
            );
          });
          
          log(`💰 Paiement confirmé: ${invoice.id} (${receivedBTC} BTC)`);
          await activatePremiumAccount(invoice.user_id, invoice.plan, invoice.id, receivedBTC);
        } else {
          log(`⏳ En attente: ${invoice.id} (${receivedBTC}/${invoice.amount} BTC)`);
        }
      } catch (error) {
        log(`❌ Erreur vérification ${invoice.id}: ${error.message}`);
      }
    }
  } catch (error) {
    log(`❌ Erreur générale checkPendingPayments: ${error.message}`);
  } finally {
    log("✅ Vérification des paiements terminée");
  }
}

// Nettoyage des abonnements expirés
async function cleanupExpiredSubscriptions() {
  try {
    log("🧹 Début nettoyage des abonnements expirés...");
    const now = new Date().toISOString();

    // SQLite cleanup
    const { changes: sqliteChanges } = await new Promise((resolve, reject) => {
      db.run(
        `UPDATE users SET plan = 'free', premium_expiry = NULL 
         WHERE premium_expiry IS NOT NULL AND premium_expiry < ?`,
        [now],
        function(err) {
          err ? reject(err) : resolve(this);
        }
      );
    });

    log(`🗑️ ${sqliteChanges} abonnement(s) expiré(s) nettoyés dans SQLite`);

    // Firestore cleanup
    const snapshot = await admin.firestore()
      .collection("Users")
      .where("subscriptionDate", "<", now)
      .get();

    const batch = admin.firestore().batch();
    snapshot.forEach(doc => {
      batch.update(doc.ref, {
        plan: "free",
        subscriptionDate: null,
        lastUpdated: admin.firestore.FieldValue.serverTimestamp()
      });
    });

    await batch.commit();
    log(`🔥 ${snapshot.size} abonnement(s) expiré(s) nettoyés dans Firestore`);

  } catch (error) {
    log(`❌ Erreur cleanupExpiredSubscriptions: ${error.message}`);
  } finally {
    log("✅ Nettoyage des abonnements terminé");
  }
}
async function cleanupOldPendingInvoices() {
  try {
    log("🧹 Nettoyage des factures en attente de +48h...");

    const cutoffDate = new Date(Date.now() - 72 * 60 * 60 * 1000).toISOString();

    const { changes } = await new Promise((resolve, reject) => {
      db.run(
        `DELETE FROM invoices 
         WHERE status = 'pending' AND created_at < ?`,
        [cutoffDate],
        function (err) {
          err ? reject(err) : resolve(this);
        }
      );
    });

    log(`🗑️ ${changes} facture(s) supprimée(s) en attente de +48h`);
  } catch (error) {
    log(`❌ Erreur cleanupOldPendingInvoices: ${error.message}`);
  }
}


/**
 * Configuration des tâches planifiées
 */

// Vérification des paiements toutes les 5 minutes
setInterval(checkPendingPayments, 5 * 60 * 1000);

// Nettoyage des abonnements expirés toutes les 24 heures
setInterval(cleanupExpiredSubscriptions, 24 * 60 * 60 * 1000);

// Exécution immédiate au démarrage
checkPendingPayments();
cleanupExpiredSubscriptions();
cleanupOldPendingInvoices();
/**
 * Gestion des extractions email
 */

const processes = {};
const EXPORT_DIR = path.join(__dirname, "exports");

if (!fs.existsSync(EXPORT_DIR)) {
  fs.mkdirSync(EXPORT_DIR, { recursive: true });
}

// Gestion WebSocket
io.on("connection", (socket) => {
  log(`🔌 Nouvelle connexion WebSocket: ${socket.id}`);

  socket.on("startExtraction", ({ email, password, imap, isPremium }) => {
    if (!email || !password || !imap) {
      return socket.emit("error", { message: "Paramètres manquants" });
    }

    const id = uuidv4();
    const safeEmail = email.replace(/[^a-zA-Z0-9]/g, "_");
    const filename = `extraction-${safeEmail}-${id}.txt`;
    const filePath = path.join(EXPORT_DIR, filename);
    const limit = isPremium ? "-1" : "10";

    log(`🔍 Début extraction pour ${email} (${socket.id})`);

    try {
      const proc = spawn("python3", ["./extractor.py", email, password, imap, limit], {
        stdio: ["ignore", "pipe", "pipe"]
      });

      processes[id] = { proc, socketId: socket.id, filePath };

      // Création fichier vide
      fs.writeFileSync(filePath, "");
      socket.emit("extractionStarted", { processId: id });

      // Gestion sortie standard
      proc.stdout.on("data", (data) => {
        const lines = data.toString("utf8").split("\n").filter(Boolean);
        lines.forEach((line) => {
          if (line.startsWith("[PROGRESS_INIT]")) {
            const total = parseInt(line.replace("[PROGRESS_INIT]", "").trim());
            socket.emit("progressInit", { totalFolders: total });
          } else if (line.startsWith("[PROGRESS_UPDATE]")) {
            const current = parseInt(line.replace("[PROGRESS_UPDATE]", "").trim());
            socket.emit("progressUpdate", { currentFolder: current });
          } else {
            fs.appendFileSync(filePath, line + "\n");
            socket.emit("emailFound", { email: line });
          }
        });
      });
      

      // Gestion erreurs
      proc.stderr.on("data", (err) => {
        const errorMsg = err.toString();
        log(`❌ Erreur extraction ${email}: ${errorMsg}`);
        socket.emit("error", { message: errorMsg });
      });

      // Gestion fin de processus
      proc.on("close", (code) => {
        log(`🏁 Extraction terminée pour ${email} - Code: ${code}`);
        
        const result = {
          code,
          downloadLink: `/download/${filename}`,
          fileSize: fs.existsSync(filePath) ? fs.statSync(filePath).size : 0
        };

        socket.emit("extractionFinished", result);
        delete processes[id];
      });

    } catch (error) {
      log(`❌ Erreur démarrage extraction: ${error.message}`);
      socket.emit("error", { message: "Erreur démarrage extraction" });
    }
  });

  socket.on("stopExtraction", ({ processId }) => {
    const process = processes[processId];
    if (process) {
      log(`⏹️ Arrêt demande pour l'extraction ${processId}`);
      process.proc.kill("SIGTERM");
      delete processes[processId];
    }
  });

  socket.on("disconnect", () => {
    log(`❌ Déconnexion WebSocket: ${socket.id}`);
  });
});

// Téléchargement des fichiers
app.get("/download/:filename", (req, res) => {
  const safeFilename = path.basename(req.params.filename);
  const filePath = path.join(EXPORT_DIR, safeFilename);

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: "Fichier introuvable" });
  }

  res.download(filePath, (err) => {
    if (err) {
      log(`❌ Erreur téléchargement ${safeFilename}: ${err.message}`);
    } else {
      log(`📥 Fichier téléchargé: ${safeFilename}`);
    }
  });
});

/**
 * Gestion des erreurs globales
 */

process.on("uncaughtException", (err) => {
  log(`💥 Exception non capturée: ${err.message}`, err.stack);
});

process.on("unhandledRejection", (err) => {
  log(`💥 Rejet non capturé: ${err.message}`, err.stack);
});

/**
 * Démarrage du serveur
 */

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  log(`🚀 Serveur démarré sur le port ${PORT}`);
  log(`🔗 Environnement: ${process.env.NODE_ENV || 'development'}`);
  log(`💰 Réseau Bitcoin: ${process.env.BTC_NETWORK || 'testnet'}`);
});

// Export pour les tests
module.exports = {
  app,
  server,
  db,
  cleanupExpiredSubscriptions,
  checkPendingPayments
};