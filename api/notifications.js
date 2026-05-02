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

  // ── GET ──────────────────────────────────────────────────────────────────
  if (req.method === 'GET') {
    let query;

    if (caller.role === 'admin') {
      if (req.query.view === 'history') {
        // Panel admin: historial COMPLETO — nunca filtra user_hidden,
        // porque el historial es el registro permanente de todo lo enviado.
        query = supabase.from('notifications').select('*')
          .order('created_at', { ascending: false }).limit(200);
      } else {
        // Bell del admin en CrashLand: solo alertas del sistema (type=admin),
        // excluyendo las que el admin marcó como ocultas desde el bell.
        query = supabase.from('notifications').select('*')
          .eq('type', 'admin')
          .or('user_hidden.is.null,user_hidden.eq.false')
          .order('created_at', { ascending: false }).limit(100);
      }
    } else {
      // Docente o estudiante: sus notificaciones + broadcasts,
      // excluyendo las que él mismo marcó como ocultas.
      query = supabase.from('notifications').select('*')
        .or(`user_id.eq.${caller.id},and(user_id.is.null,type.eq.broadcast)`)
        .or('user_hidden.is.null,user_hidden.eq.false')
        .order('created_at', { ascending: false }).limit(50);
    }

    const { data, error } = await query;
    if (error) return res.status(500).json({ error: error.message });
    const unread = (data || []).filter(n => !n.read).length;
    return res.status(200).json({ notifications: data || [], unread });
  }

  // ── POST — enviar notificación (solo admin) ───────────────────────────────
  if (req.method === 'POST') {
    if (caller.role !== 'admin') return res.status(403).json({ error: 'Sin permisos' });
    const { message, user_id } = req.body;
    if (!message) return res.status(400).json({ error: 'Falta el mensaje' });
    const type = user_id ? 'user' : 'broadcast';
    const { data, error } = await supabase.from('notifications')
      .insert([{ user_id: user_id || null, message, type, read: false, user_hidden: false }])
      .select().single();
    if (error) return res.status(500).json({ error: error.message });
    return res.status(201).json(data);
  }

  // ── PUT — marcar como leída ───────────────────────────────────────────────
  if (req.method === 'PUT') {
    if (req.query.all === 'true') {
      if (caller.role === 'admin') {
        // Solo marca las del sistema (bell del admin)
        await supabase.from('notifications').update({ read: true }).eq('type', 'admin');
      } else {
        await supabase.from('notifications').update({ read: true })
          .or(`user_id.eq.${caller.id},and(user_id.is.null,type.eq.broadcast)`);
      }
      return res.status(200).json({ success: true });
    }
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: 'Falta el id' });
    const { data, error } = await supabase.from('notifications')
      .update({ read: true }).eq('id', id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json(data);
  }

  // ── DELETE ────────────────────────────────────────────────────────────────
  if (req.method === 'DELETE') {
    const { id, panel } = req.query;
    if (!id) return res.status(400).json({ error: 'Falta el id' });

    if (caller.role === 'admin') {
      if (panel === 'true') {
        // Admin borra desde el panel administrativo → DELETE real permanente
        const { error } = await supabase.from('notifications').delete().eq('id', id);
        if (error) return res.status(500).json({ error: error.message });
        return res.status(200).json({ success: true });
      } else {
        // Admin borra desde el bell de CrashLand → soft delete (ocultar),
        // el registro se conserva en el historial del panel.
        const { error } = await supabase.from('notifications')
          .update({ user_hidden: true }).eq('id', id).eq('type', 'admin');
        if (error) return res.status(500).json({ error: error.message });
        return res.status(200).json({ success: true });
      }
    }

    // Docente / Estudiante: soft delete → marca user_hidden=true.
    // El registro NUNCA se borra de la DB. Permanece en el historial del admin.
    const { data: notif } = await supabase
      .from('notifications').select('id, user_id, type').eq('id', id).maybeSingle();
    if (!notif) return res.status(404).json({ error: 'Notificación no encontrada' });

    const canHide = String(notif.user_id) === String(caller.id) || notif.user_id === null;
    if (!canHide) return res.status(403).json({ error: 'No podés eliminar esta notificación' });

    const { error } = await supabase.from('notifications')
      .update({ user_hidden: true }).eq('id', id);
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ success: true });
  }

  return res.status(405).json({ error: 'Método no permitido' });
};
