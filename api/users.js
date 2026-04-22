const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, PUT, DELETE, OPTIONS');
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

  // ── GET /api/users — listar todos con conteo de videos ──────
  if (req.method === 'GET') {
    const { data: users, error } = await supabase
      .from('users')
      .select('id, username, email, role, validated, created_at')
      .order('created_at', { ascending: false });

    if (error) return res.status(500).json({ error: error.message });

    // Contar videos por usuario
    const { data: videoCounts } = await supabase
      .from('videos').select('user_id');

    const counts = {};
    (videoCounts || []).forEach(v => {
      if (v.user_id) counts[v.user_id] = (counts[v.user_id] || 0) + 1;
    });

    const result = (users || []).map(u => ({
      ...u,
      video_count: counts[u.id] || 0
    }));

    return res.status(200).json(result);
  }

  // ── PUT /api/users?id=X — validar o cambiar rol ─────────────
  if (req.method === 'PUT') {
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: 'Falta el id' });

    const { validated, role } = req.body;
    const updates = {};
    if (validated !== undefined) updates.validated = validated;
    if (role !== undefined) updates.role = role;

    const { data, error } = await supabase
      .from('users').update(updates).eq('id', id).select().single();

    if (error) return res.status(500).json({ error: error.message });

    // Notificar al usuario si fue validado
    if (validated === true) {
      await supabase.from('notifications').insert([{
        user_id: id,
        message: '✅ Tu cuenta ha sido aprobada. Ya podés iniciar sesión en CrashTube.',
        type: 'system'
      }]);
    } else if (validated === false) {
      await supabase.from('notifications').insert([{
        user_id: id,
        message: '❌ Tu solicitud de registro fue rechazada por el administrador.',
        type: 'system'
      }]);
    }

    return res.status(200).json(data);
  }

  // ── DELETE /api/users?id=X — eliminar usuario ───────────────
  if (req.method === 'DELETE') {
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: 'Falta el id' });

    // Desasociar sus videos (no eliminarlos, solo quitar el owner)
    await supabase.from('videos').update({ user_id: null }).eq('user_id', id);

    const { error } = await supabase.from('users').delete().eq('id', id);
    if (error) return res.status(500).json({ error: error.message });

    return res.status(200).json({ success: true });
  }

  return res.status(405).json({ error: 'Método no permitido' });
};