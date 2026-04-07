const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

function verifyToken(req) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return null;
  try { return jwt.verify(auth.slice(7), process.env.JWT_SECRET); }
  catch { return null; }
}

function detectDevice(ua) {
  if (!ua) return 'Desconocido';
  if (/PlayStation 4/i.test(ua)) return 'PS4';
  if (/PlayStation 5/i.test(ua)) return 'PS5';
  if (/Xbox/i.test(ua)) return 'Xbox';
  if (/SmartTV|Smart-TV|HbbTV|Tizen|WebOS|BRAVIA/i.test(ua)) return 'Smart TV';
  if (/iPhone/i.test(ua)) return 'iPhone';
  if (/iPad/i.test(ua)) return 'iPad';
  if (/Android/i.test(ua) && /Mobile/i.test(ua)) return 'Android';
  if (/Android/i.test(ua)) return 'Android Tablet';
  if (/Macintosh|Mac OS X/i.test(ua) && !/Mobile/i.test(ua)) return 'Mac';
  if (/Windows NT/i.test(ua)) return 'Windows';
  if (/Linux/i.test(ua)) return 'Linux';
  if (/CrOS/i.test(ua)) return 'Chromebook';
  return 'Otro';
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Device-UA');
  if (req.method === 'OPTIONS') return res.status(200).end();

  // POST — registrar visita (sin video) o reproducción (con video)
  if (req.method === 'POST') {
    const { video_id } = req.body || {};
    const ua = req.headers['x-device-ua'] || req.headers['user-agent'] || '';
    const device = detectDevice(ua);
    const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
    const { data, error } = await supabase
      .from('views')
      .insert([{ video_id: video_id || null, ip, device }])
      .select('id')
      .single();
    if (error) return res.status(500).json({ error: error.message });
    return res.status(201).json({ id: data.id, device });
  }

  // PATCH — actualizar video_id cuando empieza a reproducir
  if (req.method === 'PATCH') {
    const { id } = req.query;
    const { video_id } = req.body || {};
    if (!id || !video_id) return res.status(400).json({ error: 'Faltan id o video_id' });
    const { error } = await supabase
      .from('views')
      .update({ video_id })
      .eq('id', id);
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ success: true });
  }

  // GET — historial para admin
  if (req.method === 'GET') {
    const user = verifyToken(req);
    if (!user) return res.status(401).json({ error: 'No autorizado' });
    const { data, error } = await supabase
      .from('views')
      .select('*, videos(title)')
      .order('viewed_at', { ascending: false })
      .limit(100);
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json(data);
  }

  // DELETE — borrar historial
  if (req.method === 'DELETE') {
    const user = verifyToken(req);
    if (!user) return res.status(401).json({ error: 'No autorizado' });
    const { error } = await supabase.from('views').delete().neq('id', 0);
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ success: true });
  }

  return res.status(405).json({ error: 'Método no permitido' });
};