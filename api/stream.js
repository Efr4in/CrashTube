const { google } = require('googleapis');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Range');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { fileId } = req.query;
  if (!fileId) return res.status(400).json({ error: 'Falta fileId' });

  try {
    const rawKey = process.env.GOOGLE_PRIVATE_KEY || '';
    const privateKey = rawKey.includes('\\n')
      ? rawKey.replace(/\\n/g, '\n')
      : rawKey;

    const auth = new google.auth.GoogleAuth({
      credentials: {
        client_email: process.env.GOOGLE_CLIENT_EMAIL,
        private_key: privateKey,
      },
      scopes: ['https://www.googleapis.com/auth/drive.readonly'],
    });

    const drive = google.drive({ version: 'v3', auth });

    // Obtener metadata
    const meta = await drive.files.get({ fileId, fields: 'mimeType,size' });
    const mimeType = meta.data.mimeType || 'video/mp4';
    const fileSize = parseInt(meta.data.size || '0');

    // Siempre responder con un rango — PS4 y otros browsers necesitan
    // Content-Length exacto + 206 Partial Content para empezar a reproducir
    const rangeHeader = req.headers['range'];
    let start = 0;
    let end = Math.min(fileSize - 1, 2 * 1024 * 1024 - 1); // 2MB por defecto

    if (rangeHeader) {
      const parts = rangeHeader.replace(/bytes=/, '').split('-');
      start = parseInt(parts[0], 10);
      end = parts[1]
        ? parseInt(parts[1], 10)
        : Math.min(start + 2 * 1024 * 1024 - 1, fileSize - 1);
    }

    // Asegurarse de que end no supera el archivo
    if (end >= fileSize) end = fileSize - 1;
    const chunkSize = end - start + 1;

    res.setHeader('Content-Range', `bytes ${start}-${end}/${fileSize}`);
    res.setHeader('Accept-Ranges', 'bytes');
    res.setHeader('Content-Length', chunkSize);
    res.setHeader('Content-Type', mimeType);
    res.setHeader('Content-Disposition', 'inline');
    res.setHeader('Cache-Control', 'no-cache');
    res.status(206);

    const streamResp = await drive.files.get(
      { fileId, alt: 'media' },
      {
        responseType: 'stream',
        headers: { Range: `bytes=${start}-${end}` },
      }
    );

    streamResp.data.pipe(res);

  } catch (err) {
    console.error('ERROR STREAM:', err.message);
    if (!res.headersSent) {
      res.status(500).json({ error: err.message });
    }
  }
};
