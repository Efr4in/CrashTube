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

  // ── GET /api/videos — público, no requiere auth ─────────────
  if (req.method === 'GET') {
    const { data, error } = await supabase
      .from('videos')
      .select('id, title, drive_url, category, year, description, thumb_url, user_id, created_at')
      .order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json(data);
  }

  // Todo lo demás requiere auth
  const caller = verifyToken(req);
  if (!caller) return res.status(401).json({ error: 'No autorizado' });

  // ── POST /api/videos — subir video (user o admin) ───────────
  if (req.method === 'POST') {
    const { title, drive_url, category, year, description, thumb_url } = req.body;
    if (!title || !drive_url) return res.status(400).json({ error: 'Faltan campos requeridos' });

    const { data, error } = await supabase
      .from('videos')
      .insert([{ title, drive_url, category, year, description, thumb_url, user_id: caller.id }])
      .select().single();

    if (error) return res.status(500).json({ error: error.message });

    // Notificar a todos los usuarios que hay un nuevo video
    await supabase.from('notifications').insert([{
      user_id: null,
      message: `🎬 Nuevo video disponible: "${title}"`,
      type: 'broadcast'
    }]);

    return res.status(201).json(data);
  }

  // ── PUT /api/videos?id=X — editar video ─────────────────────
  if (req.method === 'PUT') {
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: 'Falta el id' });

    // Verificar que el video existe y obtener su owner
    const { data: video, error: fetchErr } = await supabase
      .from('videos').select('user_id').eq('id', id).single();

    if (fetchErr || !video) return res.status(404).json({ error: 'Video no encontrado' });

    // Solo puede editar si es el dueño o es admin
    const isOwner = String(video.user_id) === String(caller.id);
    const isAdmin = caller.role === 'admin';
    if (!isOwner && !isAdmin)
      return res.status(403).json({ error: 'No tenés permiso para editar este video' });

    const { title, drive_url, category, year, description, thumb_url } = req.body;
    const { data, error } = await supabase
      .from('videos').update({ title, drive_url, category, year, description, thumb_url })
      .eq('id', id).select().single();

    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json(data);
  }

  // ── DELETE /api/videos?id=X — eliminar video ────────────────
  if (req.method === 'DELETE') {
    const { id } = req.query;
    if (!id) return res.status(400).json({ error: 'Falta el id' });

    const { data: video, error: fetchErr } = await supabase
      .from('videos').select('user_id').eq('id', id).single();

    if (fetchErr || !video) return res.status(404).json({ error: 'Video no encontrado' });

    const isOwner = String(video.user_id) === String(caller.id);
    const isAdmin = caller.role === 'admin';
    if (!isOwner && !isAdmin)
      return res.status(403).json({ error: 'No tenés permiso para eliminar este video' });

    const { error } = await supabase.from('videos').delete().eq('id', id);
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ success: true });
  }

  return res.status(405).json({ error: 'Método no permitido' });
};