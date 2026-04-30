const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
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

  // ── GET /api/auth?action=me ──────────────────────────────────────────────
  if (req.method === 'GET' && action === 'me') {
    const user = verifyToken(req);
    if (!user) return res.status(401).json({ error: 'No autenticado' });
    return res.status(200).json(user);
  }

  // ── GET /api/auth?action=students (solo admin) ───────────────────────────
  if (req.method === 'GET' && action === 'students') {
    const caller = verifyToken(req);
    if (!caller || caller.role !== 'admin')
      return res.status(403).json({ error: 'Sin permisos' });

    const { data: students, error } = await supabase
      .from('students')
      .select('id, code, created_at')
      .order('created_at', { ascending: false });

    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json(students || []);
  }

  // ── DELETE /api/auth?action=delete-student&id=xxx (solo admin) ───────────
  if (req.method === 'DELETE' && action === 'delete-student') {
    const caller = verifyToken(req);
    if (!caller || caller.role !== 'admin')
      return res.status(403).json({ error: 'Sin permisos' });

    const id = req.query.id;
    if (!id) return res.status(400).json({ error: 'ID requerido' });

    const { error } = await supabase.from('students').delete().eq('id', id);
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ success: true });
  }

  if (req.method !== 'POST')
    return res.status(405).json({ error: 'Método no permitido' });

  // ── POST /api/auth?action=login ──────────────────────────────────────────
  if (action === 'login') {
    const { username, password, type } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'Faltan credenciales' });

    // ── LOGIN ESTUDIANTE ───────────────────────────────────────────────────
    if (type === 'student') {
      if (!/^\d{4}$/.test(username) || !/^\d{4}$/.test(password))
        return res.status(400).json({ error: 'El código debe ser de 4 dígitos numéricos' });

      const { data: student } = await supabase
        .from('students').select('*').eq('code', username).maybeSingle();

      if (!student)
        return res.status(401).json({ error: 'Código de estudiante no encontrado' });

      const valid = await bcrypt.compare(password, student.code_hash);
      if (!valid)
        return res.status(401).json({ error: 'Código incorrecto' });

      const token = signToken({ id: student.id, username: student.code, role: 'student' });
      return res.status(200).json({
        token,
        id: student.id,
        username: student.code,
        role: 'student'
      });
    }

    // ── LOGIN ADMIN ────────────────────────────────────────────────────────
    const { data: admin } = await supabase
      .from('admins').select('*').eq('username', username).maybeSingle();

    if (admin) {
      const valid = await bcrypt.compare(password, admin.password_hash);
      if (!valid) return res.status(401).json({ error: 'Contraseña incorrecta' });
      const token = signToken({ id: admin.id, username: admin.username, role: 'admin' });
      return res.status(200).json({
        token, id: admin.id, username: admin.username, role: 'admin'
      });
    }

    // ── LOGIN DOCENTE ──────────────────────────────────────────────────────
    const { data: user } = await supabase
      .from('users').select('*').eq('username', username).maybeSingle();

    if (!user)
      return res.status(401).json({ error: 'Usuario no encontrado' });
    if (!user.validated)
      return res.status(403).json({ error: 'Tu cuenta aún no fue aprobada por el administrador.' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Contraseña incorrecta' });

    const token = signToken({
      id: user.id, username: user.username,
      full_name: user.full_name, role: user.role || 'user'
    });
    return res.status(200).json({
      token, id: user.id, username: user.username,
      full_name: user.full_name, role: user.role || 'user'
    });
  }

  // ── POST /api/auth?action=register (docente) ─────────────────────────────
  if (action === 'register') {
    const { username, password, full_name, subject_area, email, device_fingerprint } = req.body;
    if (!username || !password || !full_name)
      return res.status(400).json({ error: 'Nombre completo, usuario y contraseña son obligatorios' });
    if (password.length < 6)
      return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });

    if (device_fingerprint) {
      const { data: existingDevice } = await supabase
        .from('users').select('id, username, validated')
        .eq('device_fingerprint', device_fingerprint).maybeSingle();
      if (existingDevice) {
        return res.status(409).json({
          error: existingDevice.validated
            ? 'Ya existe una cuenta registrada desde este dispositivo.'
            : `Ya hay una solicitud pendiente desde este dispositivo (@${existingDevice.username}). Esperá la aprobación del administrador.`
        });
      }
    }

    let orFilter = `username.eq.${username}`;
    if (email) orFilter += `,email.eq.${email}`;
    const { data: existing } = await supabase.from('users').select('id').or(orFilter).maybeSingle();
    if (existing)
      return res.status(409).json({ error: 'El usuario o email ya está registrado' });

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

  // ── POST /api/auth?action=register-student (solo admin) ──────────────────
  if (action === 'register-student') {
    const caller = verifyToken(req);
    if (!caller || caller.role !== 'admin')
      return res.status(403).json({ error: 'Sin permisos. Solo el administrador puede registrar estudiantes.' });

    const { code } = req.body;
    if (!code || !/^\d{4}$/.test(code))
      return res.status(400).json({ error: 'El código debe ser exactamente 4 dígitos numéricos' });

    const { data: existing } = await supabase
      .from('students').select('id').eq('code', code).maybeSingle();
    if (existing)
      return res.status(409).json({ error: `El código ${code} ya está registrado` });

    const code_hash = await bcrypt.hash(code, 10);
    const { error } = await supabase.from('students').insert([{ code, code_hash }]);
    if (error) return res.status(500).json({ error: error.message });

    return res.status(201).json({
      success: true,
      message: `Estudiante con código ${code} registrado correctamente.`
    });
  }

  return res.status(400).json({ error: 'Acción no reconocida' });
};
