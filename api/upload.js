const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const BUCKET = 'thumbnails'; // Asegurate de crear este bucket en Supabase Storage como público

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

  const { base64, filename } = req.body;
  if (!base64 || !filename) return res.status(400).json({ error: 'Faltan datos: base64 y filename son requeridos' });

  try {
    // Validar formato base64
    const match = base64.match(/^data:([a-zA-Z0-9]+\/[a-zA-Z0-9+.-]+);base64,(.+)$/);
    if (!match) return res.status(400).json({ error: 'Formato de imagen inválido. Usá JPG, PNG o WEBP.' });

    const mimeType = match[1];
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
    if (!allowedTypes.includes(mimeType)) {
      return res.status(400).json({ error: `Tipo de imagen no permitido: ${mimeType}` });
    }

    const buffer = Buffer.from(match[2], 'base64');

    // Limitar tamaño a 5MB
    if (buffer.length > 5 * 1024 * 1024) {
      return res.status(400).json({ error: 'La imagen no puede superar los 5MB' });
    }

    const ext = mimeType.split('/')[1].replace('jpeg', 'jpg');
    const safeName = `thumb_${Date.now()}_${Math.random().toString(36).slice(2)}.${ext}`;

    const { error: uploadError } = await supabase.storage
      .from(BUCKET)
      .upload(safeName, buffer, { contentType: mimeType, upsert: false });

    if (uploadError) {
      // Mensaje de error específico para bucket no encontrado
      if (uploadError.message && uploadError.message.toLowerCase().includes('bucket')) {
        return res.status(500).json({
          error: `El bucket "${BUCKET}" no existe en Supabase Storage. Crealo en: Supabase → Storage → New Bucket → "${BUCKET}" → marcar como público.`
        });
      }
      throw uploadError;
    }

    // Construir URL pública
    const { data: urlData } = supabase.storage.from(BUCKET).getPublicUrl(safeName);
    const publicUrl = urlData?.publicUrl || `${process.env.SUPABASE_URL}/storage/v1/object/public/${BUCKET}/${safeName}`;

    return res.status(200).json({ url: publicUrl, filename: safeName });

  } catch (e) {
    console.error('Upload error:', e.message);
    return res.status(500).json({ error: e.message || 'Error al subir la imagen' });
  }
};