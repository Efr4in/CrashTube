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
        // Panel admin: historial COMPLETO sin ningún filtro
        query = supabase.from('notifications').select('*')
          .order('created_at', { ascending: false }).limit(200);
      } else {
        // Bell del admin en CrashLand: alertas del sistema (type=admin)
        // que el admin no haya ocultado individualmente
        query = supabase.from('notifications').select('*')
          .eq('type', 'admin')
          .order('created_at', { ascending: false }).limit(100);
      }
    } else {
      // Docente o estudiante: sus notificaciones directas + broadcasts
      query = supabase.from('notifications').select('*')
        .or(`user_id.eq.${caller.id},and(user_id.is.null,type.eq.broadcast)`)
        .order('created_at', { ascending: false }).limit(50);
    }

    const { data, error } = await query;
    if (error) return res.status(500).json({ error: error.message });

    // Filtrar las que el caller ocultó individualmente (hidden_by contiene su ID)
    const callerId = String(caller.id);
    const visible = (data || []).filter(n => {
      const hiddenBy = Array.isArray(n.hidden_by) ? n.hidden_by : [];
      return !hiddenBy.map(String).includes(callerId);
    });

    const unread = visible.filter(n => !n.read).length;
    return res.status(200).json({ notifications: visible, unread });
  }

  // ── POST — enviar notificación (solo admin) ───────────────────────────────
  if (req.method === 'POST') {
    if (caller.role !== 'admin') return res.status(403).json({ error: 'Sin permisos' });
    const { message, user_id } = req.body;
    if (!message) return res.status(400).json({ error: 'Falta el mensaje' });
    const type = user_id ? 'user' : 'broadcast';
    const { data, error } = await supabase.from('notifications')
      .insert([{
        user_id: user_id || null,
        message,
        type,
        read: false,
        user_hidden: false,
        hidden_by: []
      }])
      .select().single();
    if (error) return res.status(500).json({ error: error.message });
    return res.status(201).json(data);
  }

  // ── PUT — marcar como leída ───────────────────────────────────────────────
  if (req.method === 'PUT') {
    if (req.query.all === 'true') {
      if (caller.role === 'admin') {
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

    // ── Admin borra desde el panel administrativo → DELETE real permanente
    if (caller.role === 'admin' && panel === 'true') {
      const { error } = await supabase.from('notifications').delete().eq('id', id);
      if (error) return res.status(500).json({ error: error.message });
      return res.status(200).json({ success: true });
    }

    // ── Cualquier usuario (incluyendo admin desde el bell) → soft delete
    // Agrega el ID del caller a hidden_by sin borrar el registro.
    // Así cada usuario oculta la notificación solo para sí mismo,
    // y el historial del panel siempre conserva todo.
    const { data: notif } = await supabase
      .from('notifications').select('id, user_id, type, hidden_by').eq('id', id).maybeSingle();

    if (!notif) return res.status(404).json({ error: 'Notificación no encontrada' });

    // Verificar que el caller tiene derecho a ocultar esta notificación
    const canHide = caller.role === 'admin'
      || String(notif.user_id) === String(caller.id)
      || notif.user_id === null; // broadcast

    if (!canHide) return res.status(403).json({ error: 'No podés eliminar esta notificación' });

    // Agregar el caller a hidden_by (sin duplicados)
    const currentHidden = Array.isArray(notif.hidden_by) ? notif.hidden_by : [];
    const callerId = String(caller.id);
    if (!currentHidden.map(String).includes(callerId)) {
      currentHidden.push(callerId);
    }

    const { error } = await supabase.from('notifications')
      .update({ hidden_by: currentHidden }).eq('id', id);
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ success: true });
  }

  return res.status(405).json({ error: 'Método no permitido' });
};
