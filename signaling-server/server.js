const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const WebSocket = require("ws");

const PORT = Number(process.env.PORT || 3001);
const HOST = process.env.HOST || "0.0.0.0";
const WS_PATH = process.env.WS_PATH || "/";
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const USERS_FILE = process.env.USERS_FILE || path.join(DATA_DIR, "users.json");
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || 1000 * 60 * 60 * 24 * 7);
const MAX_MESSAGE_BYTES = Number(process.env.MAX_MESSAGE_BYTES || 1024 * 1024);
const HEARTBEAT_INTERVAL_MS = Number(process.env.HEARTBEAT_INTERVAL_MS || 30000);
const SERVER_NAME = process.env.SERVER_NAME || "Messenger signaling server";

/**
 * Сервер предназначен для облачного запуска.
 * Он НЕ хранит сообщения пользователей: сообщения идут напрямую через WebRTC DataChannel.
 * Сервер отвечает только за:
 * 1) регистрацию и вход;
 * 2) список пользователей онлайн;
 * 3) передачу signaling-событий WebRTC между двумя клиентами.
 */

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

  if (url.pathname === "/" || url.pathname === "/health") {
    const payload = JSON.stringify({
      ok: true,
      name: SERVER_NAME,
      websocketPath: WS_PATH,
      onlineUsers: getOnlineUsers().length,
      uptimeSeconds: Math.round(process.uptime()),
      timestamp: new Date().toISOString(),
    });

    res.writeHead(200, {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    });
    res.end(payload);
    return;
  }

  res.writeHead(404, { "content-type": "application/json; charset=utf-8" });
  res.end(JSON.stringify({ ok: false, error: "Not found" }));
});

const wss = new WebSocket.Server({
  server,
  path: WS_PATH === "/" ? undefined : WS_PATH,
  maxPayload: MAX_MESSAGE_BYTES,
});

let users = loadUsers();
const sessions = new Map();
const clientsByUsername = new Map();

function nowIso() {
  return new Date().toISOString();
}

function loadUsers() {
  try {
    if (!fs.existsSync(USERS_FILE)) {
      return { users: {} };
    }

    const raw = fs.readFileSync(USERS_FILE, "utf8");
    if (!raw.trim()) {
      return { users: {} };
    }

    const parsed = JSON.parse(raw);

    // Поддержка старого формата: { users: [{ username, passwordHash, salt }] }
    if (Array.isArray(parsed.users)) {
      const migrated = { users: {} };
      for (const item of parsed.users) {
        if (item && item.username) {
          migrated.users[item.username] = {
            salt: item.salt || crypto.randomBytes(16).toString("hex"),
            passwordHash: item.passwordHash || item.password || "",
            createdAt: item.createdAt || nowIso(),
            lastLoginAt: item.lastLoginAt || null,
          };
        }
      }
      return migrated;
    }

    // Поддержка старого формата: { username: { password: "..." } }
    if (!parsed.users && typeof parsed === "object" && parsed !== null) {
      const migrated = { users: {} };
      for (const [username, value] of Object.entries(parsed)) {
        if (value && typeof value === "object") {
          const legacyPassword = String(value.password || value.passwordHash || "");
          const salt = value.salt || crypto.randomBytes(16).toString("hex");
          const passwordHash = value.passwordHash || hashPassword(legacyPassword, salt);
          migrated.users[username] = {
            salt,
            passwordHash,
            createdAt: value.createdAt || nowIso(),
            lastLoginAt: value.lastLoginAt || null,
          };
        }
      }
      return migrated;
    }

    if (!parsed.users || typeof parsed.users !== "object") {
      return { users: {} };
    }

    return parsed;
  } catch (error) {
    console.error("Cannot load users file:", error);
    return { users: {} };
  }
}

function saveUsers() {
  const tmpFile = `${USERS_FILE}.tmp`;
  fs.writeFileSync(tmpFile, JSON.stringify(users, null, 2), "utf8");
  fs.renameSync(tmpFile, USERS_FILE);
}

function isValidUsername(username) {
  return typeof username === "string" && /^[a-zA-Zа-яА-ЯёЁ0-9_.-]{3,32}$/.test(username.trim());
}

function normalizeUsername(username) {
  return String(username || "").trim();
}

function hashPassword(password, salt) {
  return crypto.scryptSync(String(password), salt, 64).toString("hex");
}

function verifyPassword(password, userRecord) {
  if (!userRecord || !userRecord.salt || !userRecord.passwordHash) {
    return false;
  }

  const actualHash = Buffer.from(hashPassword(password, userRecord.salt), "hex");
  const expectedHash = Buffer.from(userRecord.passwordHash, "hex");

  if (actualHash.length !== expectedHash.length) {
    return false;
  }

  return crypto.timingSafeEqual(actualHash, expectedHash);
}

function createSession(username) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, {
    username,
    expiresAt: Date.now() + SESSION_TTL_MS,
  });
  return token;
}

function resolveSession(token) {
  if (!token || !sessions.has(token)) {
    return null;
  }

  const session = sessions.get(token);
  if (!session || session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }

  session.expiresAt = Date.now() + SESSION_TTL_MS;
  return session.username;
}

function safeSend(ws, payload) {
  if (ws.readyState !== WebSocket.OPEN) {
    return false;
  }

  ws.send(JSON.stringify(payload));
  return true;
}

function getOnlineUsers() {
  return Array.from(clientsByUsername.entries())
    .filter(([, sockets]) => Array.from(sockets).some((socket) => socket.readyState === WebSocket.OPEN))
    .map(([username]) => username)
    .sort((a, b) => a.localeCompare(b));
}

function broadcastUsersList() {
  const payload = { type: "users:list", users: getOnlineUsers() };

  for (const sockets of clientsByUsername.values()) {
    for (const socket of sockets) {
      safeSend(socket, payload);
    }
  }
}

function attachClientToUser(ws, username, shouldBroadcast = true) {
  ws.username = username;
  ws.isAlive = true;

  if (!clientsByUsername.has(username)) {
    clientsByUsername.set(username, new Set());
  }

  clientsByUsername.get(username).add(ws);

  if (shouldBroadcast) {
    broadcastUsersList();
  }
}

function detachClient(ws) {
  const username = ws.username;
  if (!username || !clientsByUsername.has(username)) {
    return;
  }

  const sockets = clientsByUsername.get(username);
  sockets.delete(ws);

  if (sockets.size === 0) {
    clientsByUsername.delete(username);
  }

  broadcastUsersList();
}

function sendToUser(username, payload) {
  const sockets = clientsByUsername.get(username);
  if (!sockets || sockets.size === 0) {
    return false;
  }

  let delivered = false;
  for (const socket of sockets) {
    delivered = safeSend(socket, payload) || delivered;
  }

  return delivered;
}

function requireAuthenticated(ws) {
  if (!ws.username) {
    safeSend(ws, {
      type: "auth:required",
      message: "Для выполнения действия необходимо войти в аккаунт.",
    });
    return false;
  }

  return true;
}

function parseMessage(rawMessage) {
  if (Buffer.isBuffer(rawMessage)) {
    rawMessage = rawMessage.toString("utf8");
  }

  if (typeof rawMessage !== "string") {
    rawMessage = String(rawMessage);
  }

  return JSON.parse(rawMessage);
}

function handleRegister(ws, data) {
  const username = normalizeUsername(data.username);
  const password = String(data.password || "");

  if (!isValidUsername(username)) {
    safeSend(ws, {
      type: "auth:error",
      message: "Логин должен содержать 3–32 символа: буквы, цифры, '.', '_' или '-'.",
    });
    return;
  }

  if (password.length < 4) {
    safeSend(ws, {
      type: "auth:error",
      message: "Пароль должен содержать минимум 4 символа.",
    });
    return;
  }

  if (users.users[username]) {
    safeSend(ws, {
      type: "auth:error",
      message: "Пользователь с таким логином уже существует.",
    });
    return;
  }

  const salt = crypto.randomBytes(16).toString("hex");
  users.users[username] = {
    salt,
    passwordHash: hashPassword(password, salt),
    createdAt: nowIso(),
    lastLoginAt: nowIso(),
  };
  saveUsers();

  const token = createSession(username);
  attachClientToUser(ws, username, false);

  safeSend(ws, {
    type: "register:success",
    username,
    token,
    message: "Регистрация выполнена успешно.",
  });

  broadcastUsersList();
}

function handleLogin(ws, data) {
  const username = normalizeUsername(data.username);
  const password = String(data.password || "");
  const userRecord = users.users[username];

  if (!userRecord || !verifyPassword(password, userRecord)) {
    safeSend(ws, {
      type: "auth:error",
      message: "Неверный логин или пароль.",
    });
    return;
  }

  userRecord.lastLoginAt = nowIso();
  saveUsers();

  const token = createSession(username);
  attachClientToUser(ws, username, false);

  safeSend(ws, {
    type: "auth:success",
    username,
    token,
    message: "Вход выполнен успешно.",
  });

  broadcastUsersList();
}

function handleToken(ws, data) {
  const usernameFromToken = resolveSession(data.token);
  const username = normalizeUsername(data.username || usernameFromToken);

  if (!usernameFromToken || usernameFromToken !== username || !users.users[username]) {
    safeSend(ws, {
      type: "auth:error",
      message: "Сессия истекла. Выполните вход заново.",
    });
    return;
  }

  attachClientToUser(ws, username, false);

  safeSend(ws, {
    type: "auth:success",
    username,
    token: data.token,
    message: "Сессия восстановлена.",
  });

  broadcastUsersList();
}

function handleLogout(ws) {
  if (ws.username) {
    for (const [token, session] of sessions.entries()) {
      if (session.username === ws.username) {
        sessions.delete(token);
      }
    }
  }

  safeSend(ws, {
    type: "auth:required",
    message: "Вы вышли из аккаунта.",
  });

  detachClient(ws);
  ws.username = null;
}

function handleChatRequest(ws, data) {
  if (!requireAuthenticated(ws)) return;

  const to = normalizeUsername(data.to);
  if (!to || to === ws.username) {
    safeSend(ws, { type: "error", message: "Некорректный получатель запроса." });
    return;
  }

  if (!sendToUser(to, { type: "chat:incoming-request", from: ws.username })) {
    safeSend(ws, { type: "error", message: "Пользователь сейчас не в сети." });
    return;
  }

  safeSend(ws, { type: "chat:request-sent", to });
}

function handleChatAccept(ws, data) {
  if (!requireAuthenticated(ws)) return;

  const to = normalizeUsername(data.to);
  if (!to || to === ws.username) {
    safeSend(ws, { type: "error", message: "Некорректный получатель подтверждения." });
    return;
  }

  if (!sendToUser(to, { type: "chat:accepted", from: ws.username })) {
    safeSend(ws, { type: "error", message: "Пользователь уже отключился." });
  }
}

function relayWebRtc(ws, data, payloadKey) {
  if (!requireAuthenticated(ws)) return;

  const to = normalizeUsername(data.to);
  if (!to || to === ws.username || !data[payloadKey]) {
    safeSend(ws, { type: "error", message: "Некорректное WebRTC-сообщение." });
    return;
  }

  const delivered = sendToUser(to, {
    type: data.type,
    from: ws.username,
    [payloadKey]: data[payloadKey],
  });

  if (!delivered) {
    safeSend(ws, { type: "error", message: "Не удалось доставить WebRTC-сообщение: пользователь оффлайн." });
  }
}

function handleClientMessage(ws, rawMessage) {
  let data;

  try {
    data = parseMessage(rawMessage);
  } catch (error) {
    safeSend(ws, { type: "error", message: "Сервер получил некорректный JSON." });
    return;
  }

  if (!data || typeof data.type !== "string") {
    safeSend(ws, { type: "error", message: "В сообщении отсутствует поле type." });
    return;
  }

  switch (data.type) {
    case "auth:register":
      handleRegister(ws, data);
      break;
    case "auth:login":
      handleLogin(ws, data);
      break;
    case "auth:token":
      handleToken(ws, data);
      break;
    case "auth:logout":
      handleLogout(ws);
      break;
    case "users:get":
      if (requireAuthenticated(ws)) {
        safeSend(ws, { type: "users:list", users: getOnlineUsers() });
      }
      break;
    case "chat:request":
      handleChatRequest(ws, data);
      break;
    case "chat:accept":
      handleChatAccept(ws, data);
      break;
    case "webrtc:offer":
      relayWebRtc(ws, data, "offer");
      break;
    case "webrtc:answer":
      relayWebRtc(ws, data, "answer");
      break;
    case "webrtc:ice-candidate":
      relayWebRtc(ws, data, "candidate");
      break;
    default:
      safeSend(ws, { type: "error", message: `Неизвестный тип сообщения: ${data.type}` });
  }
}

wss.on("connection", (ws, req) => {
  ws.username = null;
  ws.isAlive = true;

  console.log(`[ws] client connected from ${req.socket.remoteAddress}`);

  ws.on("pong", () => {
    ws.isAlive = true;
  });

  ws.on("message", (rawMessage) => handleClientMessage(ws, rawMessage));

  ws.on("close", () => {
    detachClient(ws);
    console.log("[ws] client disconnected");
  });

  ws.on("error", (error) => {
    console.error("[ws] socket error:", error.message);
  });
});

const heartbeatTimer = setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) {
      detachClient(ws);
      ws.terminate();
      continue;
    }

    ws.isAlive = false;
    ws.ping();
  }
}, HEARTBEAT_INTERVAL_MS);

function shutdown(signal) {
  console.log(`[server] received ${signal}, shutting down...`);
  clearInterval(heartbeatTimer);
  broadcastUsersList();
  wss.close(() => {
    server.close(() => process.exit(0));
  });

  setTimeout(() => process.exit(1), 5000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

server.listen(PORT, HOST, () => {
  console.log(`${SERVER_NAME} started on ${HOST}:${PORT}`);
  console.log(`HTTP health endpoint: http://${HOST}:${PORT}/health`);
  console.log(`WebSocket path: ${WS_PATH}`);
});
