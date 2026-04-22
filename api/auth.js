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

  // GET /api/auth?action=me
  if (req.method === 'GET' && action === 'me') {
    const user = verifyToken(req);
    if (!user) return res.status(401).json({ error: 'No autenticado' });
    return res.status(200).json(user);
  }

  if (req.method !== 'POST') return res.status(405).json({ error: 'Método no permitido' });

  // POST /api/auth?action=login
  if (action === 'login') {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Faltan credenciales' });

    // 1. Buscar en admins (super admin)
    const { data: admin } = await supabase
      .from('admins').select('*').eq('username', username).maybeSingle();

    if (admin) {
      const valid = await bcrypt.compare(password, admin.password_hash);
      if (!valid) return res.status(401).json({ error: 'Contraseña incorrecta' });
      const token = signToken({ id: admin.id, username: admin.username, role: 'admin' });
      // ✅ id incluido para que SESSION.id funcione en el panel admin
      return res.status(200).json({ token, id: admin.id, username: admin.username, role: 'admin' });
    }

    // 2. Buscar en users (profesores)
    const { data: user } = await supabase
      .from('users').select('*').eq('username', username).maybeSingle();

    if (!user) return res.status(401).json({ error: 'Usuario no encontrado' });
    if (!user.validated) return res.status(403).json({ error: 'Tu cuenta aún no fue aprobada por el administrador.' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Contraseña incorrecta' });

    const token = signToken({ id: user.id, username: user.username, full_name: user.full_name, role: user.role || 'user' });
    // ✅ id incluido — esto era el bug: sin id, SESSION.id era undefined
    // y el filtro en teacher.html nunca encontraba los videos del docente
    return res.status(200).json({
      token,
      id: user.id,
      username: user.username,
      full_name: user.full_name,
      role: user.role || 'user'
    });
  }

  // POST /api/auth?action=register
  if (action === 'register') {
    const { username, password, full_name, subject_area, email, device_fingerprint } = req.body;
    if (!username || !password || !full_name)
      return res.status(400).json({ error: 'Nombre completo, usuario y contraseña son obligatorios' });
    if (password.length < 6)
      return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });

    // Control de dispositivo único
    if (device_fingerprint) {
      const { data: existingDevice } = await supabase
        .from('users').select('id, username, validated').eq('device_fingerprint', device_fingerprint).maybeSingle();
      if (existingDevice) {
        return res.status(409).json({
          error: existingDevice.validated
            ? 'Ya existe una cuenta registrada desde este dispositivo.'
            : `Ya hay una solicitud pendiente desde este dispositivo (@${existingDevice.username}). Esperá la aprobación del administrador.`
        });
      }
    }

    // Verificar username / email duplicados
    let orFilter = `username.eq.${username}`;
    if (email) orFilter += `,email.eq.${email}`;
    const { data: existing } = await supabase.from('users').select('id').or(orFilter).maybeSingle();
    if (existing) return res.status(409).json({ error: 'El usuario o email ya está registrado' });

    const password_hash = await bcrypt.hash(password, 10);
    const { error } = await supabase.from('users').insert([{
      username, password_hash, full_name,
      subject_area: subject_area || null,
      email: email || null,
      device_fingerprint: device_fingerprint || null,
      role: 'user', validated: false
    }]);
    if (error) return res.status(500).json({ error: error.message });

    await supabase.from('notifications').insert([{
      user_id: null,
      message: `📋 Nueva solicitud: ${full_name} (@${username})${subject_area ? ` — ${subject_area}` : ''}`,
      type: 'admin', read: false
    }]);

    return res.status(201).json({
      success: true,
      message: 'Solicitud enviada. El administrador revisará tu registro pronto.'
    });
  }

  return res.status(400).json({ error: 'Acción no reconocida' });
};
