const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

function signToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' });
}

function verifyToken(req) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return null;
  try { return jwt.verify(auth.slice(7), process.env.JWT_SECRET); }
  catch { return null; }
}

module.exports = async (req, res) => {
  cors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  const action = req.query.action;

  // ── GET /api/auth?action=me ─────────────────────────────────
  if (req.method === 'GET' && action === 'me') {
    const user = verifyToken(req);
    if (!user) return res.status(401).json({ error: 'No autenticado' });
    return res.status(200).json(user);
  }

  if (req.method !== 'POST') return res.status(405).json({ error: 'Método no permitido' });

  // ── POST /api/auth?action=login ─────────────────────────────
  if (action === 'login') {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Faltan credenciales' });

    // 1. Intentar como admin (tabla admins legacy)
    const { data: admin } = await supabase
      .from('admins').select('*').eq('username', username).single();

    if (admin) {
      const valid = await bcrypt.compare(password, admin.password_hash);
      if (!valid) return res.status(401).json({ error: 'Contraseña incorrecta' });
      const token = signToken({ id: admin.id, username: admin.username, role: 'admin' });
      return res.status(200).json({ token, username: admin.username, role: 'admin' });
    }

    // 2. Intentar como usuario normal (tabla users)
    const { data: user, error } = await supabase
      .from('users').select('*').eq('username', username).single();

    if (error || !user) return res.status(401).json({ error: 'Usuario no encontrado' });
    if (!user.validated) return res.status(403).json({ error: 'Tu cuenta aún no fue aprobada por el administrador.' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Contraseña incorrecta' });

    const token = signToken({ id: user.id, username: user.username, role: user.role });
    return res.status(200).json({ token, username: user.username, role: user.role });
  }

  // ── POST /api/auth?action=register ─────────────────────────
  if (action === 'register') {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ error: 'Faltan campos requeridos' });
    if (password.length < 6)
      return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });

    // Verificar duplicados
    const { data: existing } = await supabase
      .from('users').select('id').or(`username.eq.${username},email.eq.${email}`).maybeSingle();
    if (existing) return res.status(409).json({ error: 'El usuario o email ya está registrado' });

    const password_hash = await bcrypt.hash(password, 10);
    const { data: newUser, error } = await supabase
      .from('users').insert([{ username, email, password_hash, role: 'user', validated: false }])
      .select().single();

    if (error) return res.status(500).json({ error: error.message });

    // Notificación al admin: nuevo registro pendiente
    await supabase.from('notifications').insert([{
      user_id: null, // null = para admins / sistema
      message: `📋 Nuevo registro pendiente: @${username} (${email})`,
      type: 'admin'
    }]);

    return res.status(201).json({
      success: true,
      message: 'Registro enviado. El administrador debe aprobar tu cuenta antes de que puedas ingresar.'
    });
  }

  return res.status(400).json({ error: 'Acción no reconocida' });
};