const { createClient } = require('@supabase/supabase-js');
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

  // ── GET /api/notifications — notificaciones del usuario logueado ──
  if (req.method === 'GET') {
    let query;

    if (caller.role === 'admin') {
      // Admin ve las de tipo 'admin' (registros pendientes, etc.)
      query = supabase
        .from('notifications')
        .select('*')
        .eq('type', 'admin')
        .order('created_at', { ascending: false })
        .limit(50);
    } else {
      // Usuario ve las suyas (user_id = su id) O las globales (user_id = null, type = 'broadcast')
      query = supabase
        .from('notifications')
        .select('*')
        .or(`user_id.eq.${caller.id},and(user_id.is.null,type.eq.broadcast)`)
        .order('created_at', { ascending: false })
        .limit(50);
    }

    const { data, error } = await query;
    if (error) return res.status(500).json({ error: error.message });

    const unread = (data || []).filter(n => !n.read).length;
    return res.status(200).json({ notifications: data || [], unread });
  }

  // ── POST /api/notifications — crear notificación (solo admin) ──
  if (req.method === 'POST') {
    if (caller.role !== 'admin') return res.status(403).json({ error: 'Solo el administrador puede enviar notificaciones' });

    const { message, user_id, type } = req.body; // user_id = null → broadcast a todos
    if (!message) return res.status(400).json({ error: 'Falta el mensaje' });

    const notifType = user_id ? 'user' : (type || 'broadcast');

    if (user_id) {
      // Notificación a usuario específico
      const { data, error } = await supabase
        .from('notifications')
        .insert([{ user_id, message, type: notifType, read: false }])
        .select().single();
      if (error) return res.status(500).json({ error: error.message });
      return res.status(201).json(data);
    } else {
      // Broadcast: insertar una entrada con user_id null y type 'broadcast'
      const { data, error } = await supabase
        .from('notifications')
        .insert([{ user_id: null, message, type: 'broadcast', read: false }])
        .select().single();
      if (error) return res.status(500).json({ error: error.message });
      return res.status(201).json(data);
    }
  }

  // ── PUT /api/notifications?id=X — marcar como leída ─────────
  if (req.method === 'PUT') {
    const { id } = req.query;
    const markAll = req.query.all === 'true';

    if (markAll) {
      // Marcar todas como leídas para este usuario
      if (caller.role === 'admin') {
        await supabase.from('notifications').update({ read: true }).eq('type', 'admin');
      } else {
        await supabase.from('notifications').update({ read: true })
          .or(`user_id.eq.${caller.id},and(user_id.is.null,type.eq.broadcast)`);
      }
      return res.status(200).json({ success: true });
    }

    if (!id) return res.status(400).json({ error: 'Falta el id' });
    const { data, error } = await supabase
      .from('notifications').update({ read: true }).eq('id', id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json(data);
  }

  // ── DELETE /api/notifications?id=X — eliminar (solo admin) ──
  if (req.method === 'DELETE') {
    if (caller.role !== 'admin') return res.status(403).json({ error: 'Sin permisos' });
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: 'Falta el id' });
    const { error } = await supabase.from('notifications').delete().eq('id', id);
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ success: true });
  }

  return res.status(405).json({ error: 'Método no permitido' });
};