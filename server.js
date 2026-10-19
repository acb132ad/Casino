const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');

const app = express();
const SECRET = process.env.JWT_SECRET || require('crypto').randomBytes(32).toString('hex');

const DB_DIR = fs.existsSync('/data') ? '/data' : __dirname;
const db = new Database(path.join(DB_DIR, 'casino.db'));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  balance INTEGER NOT NULL DEFAULT 0,
  role TEXT NOT NULL DEFAULT 'user',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  amount INTEGER NOT NULL,
  type TEXT NOT NULL,
  note TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

app.use(express.json());
app.use(cookieParser());

function auth(requiredRole) {
  return (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Chưa đăng nhập' });
    try {
      const payload = jwt.verify(token, SECRET);
      req.user = payload;
      if (requiredRole && payload.role !== requiredRole)
        return res.status(403).json({ error: 'Không có quyền' });
      next();
    } catch {
      return res.status(401).json({ error: 'Token không hợp lệ' });
    }
  };
}

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Thiếu dữ liệu' });
  const hash = await bcrypt.hash(password, 10);
  try {
    db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(username, hash);
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: 'Tên đã tồn tại' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !(await bcrypt.compare(password, user.password_hash)))
    return res.status(401).json({ error: 'Sai thông tin' });
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: true });
  res.json({ ok: true, role: user.role });
});

app.post('/api/logout', (req, res) => { res.clearCookie('token'); res.json({ ok: true }); });

app.get('/api/me', auth(), (req, res) => {
  res.json(db.prepare('SELECT id, username, balance, role FROM users WHERE id = ?').get(req.user.id));
});

app.get('/api/admin/users', auth('admin'), (req, res) => {
  res.json(db.prepare('SELECT id, username, balance, role, created_at FROM users').all());
});

app.post('/api/admin/credit', auth('admin'), (req, res) => {
  const { user_id, amount, note } = req.body;
  if (!Number.isInteger(amount) || amount <= 0)
    return res.status(400).json({ error: 'Số tiền phải là số nguyên dương' });
  const tx = db.transaction(() => {
    db.prepare('UPDATE users SET balance = balance + ? WHERE id = ?').run(amount, user_id);
    db.prepare('INSERT INTO transactions (user_id, amount, type, note) VALUES (?, ?, ?, ?)')
      .run(user_id, amount, 'credit', note || '');
  });
  tx();
  res.json({ ok: true });
});

app.post('/api/admin/debit', auth('admin'), (req, res) => {
  const { user_id, amount, note } = req.body;
  if (!Number.isInteger(amount) || amount <= 0)
    return res.status(400).json({ error: 'Số tiền phải là số nguyên dương' });
  const user = db.prepare('SELECT balance FROM users WHERE id = ?').get(user_id);
  if (!user) return res.status(404).json({ error: 'Không tìm thấy người dùng' });
  if (user.balance < amount) return res.status(400).json({ error: 'Số dư không đủ' });
  const tx = db.transaction(() => {
    db.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').run(amount, user_id);
    db.prepare('INSERT INTO transactions (user_id, amount, type, note) VALUES (?, ?, ?, ?)')
      .run(user_id, amount, 'debit', note || '');
  });
  tx();
  res.json({ ok: true });
});

app.get('/api/admin/transactions/:user_id', auth('admin'), (req, res) => {
  res.json(db.prepare('SELECT * FROM transactions WHERE user_id = ? ORDER BY id DESC').all(req.params.user_id));
});

app.post('/api/bootstrap-admin', async (req, res) => {
  const exists = db.prepare("SELECT 1 FROM users WHERE role = 'admin'").get();
  if (exists) return res.status(400).json({ error: 'Admin đã tồn tại' });
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Thiếu dữ liệu' });
  const hash = await bcrypt.hash(password, 10);
  db.prepare("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')").run(username, hash);
  res.json({ ok: true });
});

// ===== TRÒ CHƠI: TÀI XỈU =====
function rollDice() {
  return [1,2,3].map(() => Math.floor(Math.random() * 6) + 1);
}

app.post('/api/game/taixiu', auth(), (req, res) => {
  const { bet, choice } = req.body;
  if (!Number.isInteger(bet) || bet <= 0)
    return res.status(400).json({ error: 'Cược phải là số nguyên dương' });
  if (choice !== 'tai' && choice !== 'xiu')
    return res.status(400).json({ error: 'Chọn "tai" hoặc "xiu"' });

  const user = db.prepare('SELECT balance FROM users WHERE id = ?').get(req.user.id);
  if (user.balance < bet) return res.status(400).json({ error: 'Số dư không đủ' });

  const dice = rollDice();
  const total = dice.reduce((a, b) => a + b, 0);
  let result;
  if (total === 3 || total === 18) result = 'house';
  else if (total >= 11) result = 'tai';
  else result = 'xiu';

  let win = false;
  let payout = 0;
  if (result === choice) {
    win = true;
    payout = bet * 2;
  }

  const tx = db.transaction(() => {
    if (win) {
      db.prepare('UPDATE users SET balance = balance - ? + ? WHERE id = ?').run(bet, payout, req.user.id);
      db.prepare('INSERT INTO transactions (user_id, amount, type, note) VALUES (?, ?, ?, ?)')
        .run(req.user.id, payout - bet, 'win', `Tài Xỉu ${dice.join('-')} tổng ${total} (${result})`);
    } else {
      db.prepare('UPDATE users SET balance = balance - ? WHERE id = ?').run(bet, req.user.id);
      db.prepare('INSERT INTO transactions (user_id, amount, type, note) VALUES (?, ?, ?, ?)')
        .run(req.user.id, bet, 'lose', `Tài Xỉu ${dice.join('-')} tổng ${total} (${result})`);
    }
  });
  tx();

  const newBalance = db.prepare('SELECT balance FROM users WHERE id = ?').get(req.user.id).balance;
  res.json({ dice, total, result, win, bet, payout, balance: newBalance });
});

const HTML = `<!DOCTYPE html>
<html lang="vi"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Casino Online</title>
<style>
body{font-family:sans-serif;max-width:600px;margin:40px auto;padding:0 16px}
input,button,select{padding:8px;margin:4px 0;width:100%;box-sizing:border-box}
.box{border:1px solid #ccc;padding:16px;margin-bottom:16px;border-radius:6px}
pre{background:#f4f4f4;padding:8px;overflow:auto;max-height:300px}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:4px;font-size:13px}
.quick-bet{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px}
.quick-bet button{width:auto;flex:1;min-width:90px}
</style></head><body>
<div class="box"><h3>Đăng ký / Đăng nhập</h3>
<input id="u" placeholder="Tên đăng nhập"><input id="p" type="password" placeholder="Mật khẩu">
<button onclick="register()">Đăng ký</button><button onclick="login()">Đăng nhập</button></div>
<div class="box"><h3>Tài khoản</h3><button onclick="loadMe()">Tải thông tin</button>
<pre id="me"></pre><button onclick="logout()">Đăng xuất</button></div>
<div class="box" id="gamePanel" style="display:none">
  <h3>Tài Xỉu</h3>
  <div class="quick-bet">
    <button onclick="setBet(10000)">10.000đ</button>
    <button onclick="setBet(50000)">50.000đ</button>
    <button onclick="setBet(100000)">100.000đ</button>
  </div>
  <input id="bet" placeholder="Số tiền cược" type="number" min="1" step="1000">
  <select id="choice">
    <option value="tai">Tài (11-17)</option>
    <option value="xiu">Xỉu (4-10)</option>
  </select>
  <button onclick="playTaiXiu()">Đặt cược</button>
  <pre id="gameResult"></pre>
</div>
<div class="box" id="adminPanel" style="display:none"><h3>Quản trị</h3>
<button onclick="loadUsers()">Tải danh sách người dùng</button>
<table id="tbl"><thead><tr><th>ID</th><th>Tên</th><th>Số dư</th><th>Vai trò</th></tr></thead><tbody></tbody></table>
<input id="uid" placeholder="ID người dùng" type="number">
<input id="amt" placeholder="Số tiền" type="number">
<input id="note" placeholder="Ghi chú">
<button onclick="credit()">Cộng tiền</button><button onclick="debit()">Trừ tiền</button></div>
<script>
const api=(url,body)=>fetch(url,{method:body?'POST':'GET',headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined}).then(r=>r.json());
const u=()=>document.getElementById('u').value,p=()=>document.getElementById('p').value;
function register(){api('/api/register',{username:u(),password:p()}).then(alert)}
function login(){api('/api/login',{username:u(),password:p()}).then(r=>{if(r.ok){loadMe();document.getElementById('gamePanel').style.display='block';if(r.role==='admin')document.getElementById('adminPanel').style.display='block'}else alert(r.error)})}
function logout(){api('/api/logout',{}).then(()=>location.reload())}
function loadMe(){api('/api/me').then(r=>document.getElementById('me').textContent=JSON.stringify(r,null,2))}
function loadUsers(){api('/api/admin/users').then(list=>{if(!Array.isArray(list))return;document.querySelector('#tbl tbody').innerHTML=list.map(x=>'<tr><td>'+x.id+'</td><td>'+x.username+'</td><td>'+x.balance+'</td><td>'+x.role+'</td></tr>').join('')})}
function credit(){api('/api/admin/credit',{user_id:+document.getElementById('uid').value,amount:+document.getElementById('amt').value,note:document.getElementById('note').value}).then(r=>{alert(JSON.stringify(r));loadUsers()})}
function debit(){api('/api/admin/debit',{user_id:+document.getElementById('uid').value,amount:+document.getElementById('amt').value,note:document.getElementById('note').value}).then(r=>{alert(JSON.stringify(r));loadUsers()})}
function setBet(v){document.getElementById('bet').value=v}
function playTaiXiu(){api('/api/game/taixiu',{bet:+document.getElementById('bet').value,choice:document.getElementById('choice').value}).then(r=>{document.getElementById('gameResult').textContent=JSON.stringify(r,null,2);loadMe()})}
</script></body></html>`;

app.get('/', (req, res) => res.type('html').send(HTML));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`Server chạy tại cổng ${PORT}`));