const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = path.join(__dirname, "public");
const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");

fs.mkdirSync(PUBLIC_DIR, { recursive: true });
fs.mkdirSync(DATA_DIR, { recursive: true });

if (!fs.existsSync(USERS_FILE)) {
  fs.writeFileSync(USERS_FILE, "[]", "utf8");
}

app.disable("x-powered-by");

app.use(express.json({ limit: "1mb" }));
app.use(express.static(PUBLIC_DIR));

function readUsers() {
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
  } catch {
    return [];
  }
}

function writeUsers(users) {
  const tmp = USERS_FILE + ".tmp";

  fs.writeFileSync(
    tmp,
    JSON.stringify(users, null, 2),
    "utf8"
  );

  fs.renameSync(tmp, USERS_FILE);
}

function cleanMobile(value) {
  return String(value || "")
    .replace(/[^\d+]/g, "")
    .slice(0, 16);
}

function validMobile(value) {
  const number = cleanMobile(value)
    .replace(/^\+91/, "")
    .replace(/^91(?=\d{10}$)/, "");

  return /^[6-9]\d{9}$/.test(number);
}

function hashPassword(
  password,
  salt = crypto.randomBytes(16).toString("hex")
) {
  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  return {
    salt,
    hash
  };
}

function verifyPassword(password, user) {
  const hash = crypto
    .scryptSync(password, user.salt, 64)
    .toString("hex");

  return crypto.timingSafeEqual(
    Buffer.from(hash, "hex"),
    Buffer.from(user.passwordHash, "hex")
  );
}

function token() {
  return crypto.randomBytes(32).toString("hex");
}

/*
  Real SMS OTP

  Set these Environment Variables on Render
  when you are ready to connect an SMS provider:

  SMS_API_URL
  SMS_API_KEY
*/

async function sendSmsOtp(mobile, otp) {
  const url = process.env.SMS_API_URL;
  const key = process.env.SMS_API_KEY;

  if (!url || !key) {
    return false;
  }

  try {
    const response = await fetch(url, {
      method: "POST",

      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${key}`
      },

      body: JSON.stringify({
        to: mobile,
        message:
          `Your ZeeshanPlayzone- OTP is ${otp}. It expires in 5 minutes.`
      })
    });

    return response.ok;
  } catch (error) {
    console.error("SMS service error:", error);
    return false;
  }
}

const otpStore = new Map();
const sessions = new Map();

/*
  REQUEST OTP
*/

app.post("/api/auth/request-otp", async (req, res) => {
  try {
    const name = String(req.body.name || "")
      .trim()
      .slice(0, 40);

    const mobile = cleanMobile(req.body.mobile);
    const password = String(req.body.password || "");

    if (
      !name ||
      !validMobile(mobile) ||
      password.length < 8 ||
      password.length > 72
    ) {
      return res.status(400).json({
        error:
          "Please provide a valid name, Indian mobile number and password (8–72 characters)."
      });
    }

    const users = readUsers();

    let user = users.find(
      (u) => u.mobile === mobile
    );

    if (!user) {
      const passwordData = hashPassword(password);

      user = {
        id: token(),
        name,
        mobile,
        salt: passwordData.salt,
        passwordHash: passwordData.hash,
        createdAt: new Date().toISOString()
      };

      users.push(user);
    } else {
      if (!verifyPassword(password, user)) {
        return res.status(401).json({
          error: "Incorrect password."
        });
      }
    }

    const otp = String(
      crypto.randomInt(100000, 1000000)
    );

    otpStore.set(mobile, {
      otp,
      expires: Date.now() + 5 * 60 * 1000,
      attempts: 0
    });

    const sent = await sendSmsOtp(
      mobile,
      otp
    );

    if (!sent) {
      otpStore.delete(mobile);

      return res.status(503).json({
        error:
          "Real OTP service is not configured. Set SMS_API_URL and SMS_API_KEY on the server; no demo OTP is shown."
      });
    }

    writeUsers(users);

    return res.json({
      ok: true,
      message:
        "OTP sent to your mobile number."
    });
  } catch (error) {
    console.error(
      "Request OTP error:",
      error
    );

    return res.status(500).json({
      error: "Unable to request OTP."
    });
  }
});

/*
  VERIFY OTP
*/

app.post("/api/auth/verify-otp", (req, res) => {
  try {
    const mobile = cleanMobile(
      req.body.mobile
    );

    const otp = String(
      req.body.otp || ""
    ).trim();

    const record = otpStore.get(mobile);

    if (
      !record ||
      Date.now() > record.expires
    ) {
      otpStore.delete(mobile);

      return res.status(400).json({
        error:
          "OTP expired. Request a new OTP."
      });
    }

    record.attempts++;

    if (record.attempts > 5) {
      otpStore.delete(mobile);

      return res.status(429).json({
        error:
          "Too many OTP attempts."
      });
    }

    if (record.otp !== otp) {
      return res.status(401).json({
        error: "Invalid OTP."
      });
    }

    otpStore.delete(mobile);

    const user = readUsers().find(
      (u) => u.mobile === mobile
    );

    if (!user) {
      return res.status(404).json({
        error: "Account not found."
      });
    }

    const session = token();

    sessions.set(session, {
      userId: user.id,
      expires:
        Date.now() +
        24 * 60 * 60 * 1000
    });

    return res.json({
      ok: true,
      session,
      name: user.name
    });
  } catch (error) {
    console.error(
      "Verify OTP error:",
      error
    );

    return res.status(500).json({
      error: "Unable to verify OTP."
    });
  }
});

/*
  HEALTH CHECK

  Render can use this endpoint
  to check whether the server is running.
*/

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    service: "ZeeshanPlayzone-"
  });
});

/*
  EXPRESS 5 COMPATIBLE FRONTEND FALLBACK

  Do NOT use:
  app.get("*", ...)

  Express 5 throws:
  PathError: Missing parameter name at index 1: *
*/

app.use((req, res, next) => {
  if (req.method !== "GET") {
    return next();
  }

  res.sendFile(
    path.join(PUBLIC_DIR, "index.html"),
    (error) => {
      if (error) {
        next(error);
      }
    }
  );
});

/*
  ERROR HANDLER
*/

app.use((error, _req, res, _next) => {
  console.error(
    "Server error:",
    error
  );

  if (res.headersSent) {
    return;
  }

  res.status(500).json({
    error: "Internal server error."
  });
});

/*
  START SERVER

  0.0.0.0 is important for Render.
*/

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `ZeeshanPlayzone- running on port ${PORT}`
    );
  }
);
