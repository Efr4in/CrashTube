const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
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

  const caller = verifyToken(req);
  if (!caller) return res.status(401).json({ error: 'No autenticado' });
  if (caller.role !== 'admin') return res.status(403).json({ error: 'Solo el administrador puede acceder' });

  // ── GET /api/users?filter=pending|validated|all ─────────────────────────────
  if (req.method === 'GET' && !req.query.action) {
    const filter = req.query.filter || 'all';
    let query = supabase
      .from('users')
      .select('id, username, email, full_name, subject_area, role, validated, created_at, device_fingerprint')
      .order('created_at', { ascending: false });
    if (filter === 'pending')   query = query.eq('validated', false);
    if (filter === 'validated') query = query.eq('validated', true);

    const { data: users, error } = await query;
    if (error) return res.status(500).json({ error: error.message });

    // Contar videos por usuario
    const { data: vids } = await supabase.from('videos').select('user_id');
    const counts = {};
    (vids || []).forEach(v => { if (v.user_id) counts[v.user_id] = (counts[v.user_id] || 0) + 1; });

    return res.status(200).json((users || []).map(u => ({ ...u, video_count: counts[u.id] || 0 })));
  }

  // ── GET /api/users?action=admins — listar admins de la tabla admins ─────────
  if (req.method === 'GET' && req.query.action === 'admins') {
    const { data, error } = await supabase
      .from('admins')
      .select('id, username, created_at')
      .order('created_at', { ascending: true });
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json(data || []);
  }

  // ── POST /api/users?action=add-admin — crear admin de forma INMEDIATA ───────
  // Este endpoint es solo accesible desde el panel, no requiere validación
  if (req.method === 'POST' && req.query.action === 'add-admin') {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Usuario y contraseña son obligatorios' });
    if (password.length < 6) return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });

    // Verificar que no existe ese username ya
    const { data: existing } = await supabase
      .from('admins').select('id').eq('username', username).maybeSingle();
    if (existing) return res.status(409).json({ error: 'Ese nombre de usuario ya existe en administradores' });

    const hash = await bcrypt.hash(password, 10);
    const { data, error } = await supabase
      .from('admins')
      .insert([{ username, password_hash: hash }])
      .select('id, username, created_at')
      .single();
    if (error) return res.status(500).json({ error: error.message });
    return res.status(201).json(data);
  }

  // ── DELETE /api/users?action=delete-admin&id=X — eliminar admin ────────────
  if (req.method === 'DELETE' && req.query.action === 'delete-admin') {
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: 'Falta el id' });
    // No puede eliminarse a sí mismo
    if (String(id) === String(caller.id)) {
      return res.status(400).json({ error: 'No podés eliminar tu propia cuenta de administrador' });
    }
    const { error } = await supabase.from('admins').delete().eq('id', id);
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ success: true });
  }

  // ── PUT /api/users?id=X — validar/rechazar profesor ─────────────────────────
  if (req.method === 'PUT') {
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: 'Falta el id' });
    const { validated, role, rejected } = req.body;
    const updates = {};
    if (validated !== undefined) updates.validated = validated;
    if (role !== undefined) updates.role = role;

    const { data, error } = await supabase
      .from('users').update(updates).eq('id', id)
      .select('id, username, full_name, subject_area, email, role, validated, created_at')
      .single();
    if (error) return res.status(500).json({ error: error.message });

    // Notificar al usuario
    if (validated === true) {
      await supabase.from('notifications').insert([{
        user_id: id, type: 'system', read: false,
        message: '✅ Tu cuenta fue aprobada. Ya podés iniciar sesión en CrashTube.'
      }]);
    } else if (rejected) {
      await supabase.from('notifications').insert([{
        user_id: id, type: 'system', read: false,
        message: '❌ Tu solicitud de registro fue rechazada por el administrador.'
      }]);
    }
    return res.status(200).json(data);
  }

  // ── DELETE /api/users?id=X — eliminar profesor ──────────────────────────────
  if (req.method === 'DELETE' && !req.query.action) {
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: 'Falta el id' });
    await supabase.from('videos').update({ user_id: null }).eq('user_id', id);
    const { error } = await supabase.from('users').delete().eq('id', id);
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ success: true });
  }

  return res.status(405).json({ error: 'Método no permitido' });
};