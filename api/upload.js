const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
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
  if (req.method !== 'POST') return res.status(405).json({ error: 'Método no permitido' });

  const caller = verifyToken(req);
  if (!caller) return res.status(401).json({ error: 'No autorizado' });

  // Recibe: { base64: "data:image/jpeg;base64,...", filename: "portada.jpg" }
  const { base64, filename } = req.body;
  if (!base64 || !filename) return res.status(400).json({ error: 'Faltan datos' });

  try {
    // Extraer tipo MIME y datos del base64
    const match = base64.match(/^data:([a-zA-Z0-9]+\/[a-zA-Z0-9+.-]+);base64,(.+)$/);
    if (!match) return res.status(400).json({ error: 'Formato de imagen inválido' });

    const mimeType = match[1];
    const buffer = Buffer.from(match[2], 'base64');

    // Nombre único para evitar colisiones
    const ext = filename.split('.').pop().toLowerCase();
    const safeName = `thumb_${Date.now()}_${Math.random().toString(36).slice(2)}.${ext}`;

    const { error: uploadError } = await supabase.storage
      .from('thumbnails')
      .upload(safeName, buffer, { contentType: mimeType, upsert: false });

    if (uploadError) throw uploadError;

    const publicUrl = `${process.env.SUPABASE_URL}/storage/v1/object/public/thumbnails/${safeName}`;
    return res.status(200).json({ url: publicUrl });

  } catch (e) {
    console.error('Upload error:', e.message);
    return res.status(500).json({ error: e.message || 'Error al subir la imagen' });
  }
};