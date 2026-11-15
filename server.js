const express = require('express'), multer = require('multer'), fs = require('fs'),
  path = require('path'), crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const PW = process.env.ADMIN_PASSWORD;
const MAXMB = +process.env.MAX_UPLOAD_MB || 5000; // الحد الأقصى للملف الواحد بالميغا
const SECURE = process.env.COOKIE_SECURE === '1'; // فعّلها لما تستعمل HTTPS
if (!PW || PW.length < 8) { console.error('حدّد ADMIN_PASSWORD (8 أحرف على الأقل)'); process.exit(1); }
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

const DATA = path.join(__dirname, 'data'), UP = path.join(DATA, 'uploads'), DBF = path.join(DATA, 'db.json');
fs.mkdirSync(UP, { recursive: true });
let db = { videos: [], config: { banner: '', locked: false } };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(DBF, 'utf8'))); } catch (e) {}
const save = () => { fs.writeFileSync(DBF + '.tmp', JSON.stringify(db)); fs.renameSync(DBF + '.tmp', DBF); };
const rm = f => { if (f) fs.unlink(path.join(UP, path.basename(f)), () => {}); };

/* ---- المصادقة ---- */
const sign = v => crypto.createHmac('sha256', SECRET).update(v).digest('hex');
const mkToken = () => { const t = String(Date.now()); return t + '.' + sign(t); };
const hash = s => crypto.createHash('sha256').update(String(s)).digest();
const validToken = c => {
  if (!c) return false;
  const [t, s] = c.split('.');
  if (!t || !s || Date.now() - Number(t) > 7 * 864e5) return false;
  const a = Buffer.from(s), b = Buffer.from(sign(t));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const getCookie = req => ((req.headers.cookie || '').match(/(?:^|; )bt=([^;]*)/) || [])[1];
const auth = (req, res, next) => validToken(getCookie(req)) ? next() : res.status(401).json({ error: 'غير مصرّح' });
const tries = new Map();

/* ---- الرفع ---- */
const storage = multer.diskStorage({
  destination: UP,
  filename: (req, f, cb) => {
    const ext = path.extname(f.originalname).toLowerCase();
    cb(null, crypto.randomBytes(16).toString('hex') + (/^\.[a-z0-9]{1,5}$/.test(ext) ? ext : ''));
  }
});
const fileFilter = (req, f, cb) => {
  const ok = f.fieldname === 'video' ? /^video\//.test(f.mimetype) : /^image\/(jpeg|png|webp|gif)$/.test(f.mimetype);
  cb(ok ? null : new Error('نوع الملف غير مسموح'), ok);
};
const upload = multer({ storage, fileFilter, limits: { fileSize: MAXMB * 1024 * 1024 } })
  .fields([{ name: 'video', maxCount: 1 }, { name: 'thumb', maxCount: 1 }]);
const up = (req, res, next) => upload(req, res, err => err
  ? res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'الملف أكبر من الحد المسموح' : err.message })
  : next());

/* ---- التطبيق ---- */
const app = express();
app.disable('x-powered-by');
app.use((req, res, next) => { res.set('X-Content-Type-Options', 'nosniff'); next(); });
app.use(express.json({ limit: '50kb' }));
app.use('/media', express.static(UP, { maxAge: '7d', immutable: true })); // يدعم التقديم والتأخير في الفيديو
app.use(express.static(path.join(__dirname, 'public')));

const pub = v => ({ id: v.id, title: v.title, cat: v.cat, desc: v.desc, file: v.file, thumb: v.thumb, dur: v.dur, featured: v.featured });
app.get('/api/site', (req, res) => {
  const c = db.config;
  res.json({ config: { banner: c.banner, locked: c.locked }, videos: c.locked ? [] : db.videos.filter(v => !v.hidden).map(pub) });
});

app.post('/api/login', (req, res) => {
  const ip = req.ip, t = tries.get(ip) || { n: 0, at: Date.now() };
  if (Date.now() - t.at > 9e5) { t.n = 0; t.at = Date.now(); }
  if (t.n >= 10) return res.status(429).json({ error: 'محاولات كثيرة، جرّب بعد 15 دقيقة' });
  const good = crypto.timingSafeEqual(hash(req.body.password || ''), hash(PW));
  if (!good) { t.n++; tries.set(ip, t); return res.status(401).json({ error: 'كلمة السر غير صحيحة' }); }
  tries.delete(ip);
  res.cookie('bt', mkToken(), { httpOnly: true, sameSite: 'strict', secure: SECURE, maxAge: 7 * 864e5 });
  res.json({ ok: true });
});
app.post('/api/logout', (req, res) => { res.clearCookie('bt'); res.json({ ok: true }); });

app.get('/api/admin/site', auth, (req, res) => res.json({ config: db.config, videos: db.videos }));

app.post('/api/admin/videos', auth, up, (req, res) => {
  const f = req.files || {}, b = req.body;
  if (!f.video) return res.status(400).json({ error: 'اختر ملف فيديو' });
  if (!String(b.title || '').trim()) { rm(f.video[0].filename); if (f.thumb) rm(f.thumb[0].filename); return res.status(400).json({ error: 'اكتب العنوان' }); }
  const v = {
    id: crypto.randomBytes(6).toString('hex'), title: b.title.trim().slice(0, 200), cat: String(b.cat || '').trim().slice(0, 40),
    desc: String(b.desc || '').slice(0, 5000), file: f.video[0].filename, thumb: f.thumb ? f.thumb[0].filename : '',
    dur: Number(b.dur) || 0, featured: b.featured === '1', hidden: false, created: Date.now()
  };
  if (v.featured) db.videos.forEach(x => x.featured = false);
  db.videos.unshift(v); save(); res.json(v);
});

app.put('/api/admin/videos/:id', auth, up, (req, res) => {
  const v = db.videos.find(x => x.id === req.params.id), b = req.body, f = req.files || {};
  if (!v) return res.status(404).json({ error: 'غير موجود' });
  if (b.title !== undefined && b.title.trim()) v.title = b.title.trim().slice(0, 200);
  if (b.cat !== undefined) v.cat = b.cat.trim().slice(0, 40);
  if (b.desc !== undefined) v.desc = b.desc.slice(0, 5000);
  if (b.featured !== undefined) { v.featured = b.featured === '1'; if (v.featured) db.videos.forEach(x => { if (x !== v) x.featured = false; }); }
  if (b.hidden !== undefined) v.hidden = b.hidden === '1';
  if (f.thumb) { rm(v.thumb); v.thumb = f.thumb[0].filename; }
  save(); res.json(v);
});

app.delete('/api/admin/videos/:id', auth, (req, res) => {
  const i = db.videos.findIndex(x => x.id === req.params.id);
  if (i < 0) return res.status(404).json({ error: 'غير موجود' });
  const [v] = db.videos.splice(i, 1); rm(v.file); rm(v.thumb); save(); res.json({ ok: true });
});

app.put('/api/admin/config', auth, (req, res) => {
  db.config = { banner: String(req.body.banner || '').slice(0, 200), locked: !!req.body.locked };
  save(); res.json(db.config);
});

app.listen(PORT, () => console.log('Black Tube يعمل على المنفذ ' + PORT));
