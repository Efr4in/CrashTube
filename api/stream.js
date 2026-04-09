const { google } = require('googleapis');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Range, Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { fileId, mode } = req.query;
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

    const client = await auth.getClient();
    const tokenResponse = await client.getAccessToken();
    const accessToken = tokenResponse.token;

    // Modo redirect: devuelve la URL de tu propio proxy, no la de Google directa
    if (mode === 'redirect') {
      const proxyUrl = `/api/stream?fileId=${encodeURIComponent(fileId)}`;
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Content-Type', 'application/json');
      return res.status(200).json({ url: proxyUrl });
    }

    const drive = google.drive({ version: 'v3', auth });

    const meta = await drive.files.get({
      fileId,
      fields: 'mimeType,size',
      supportsAllDrives: true,
    });

    const mimeType = meta.data.mimeType || 'video/mp4';
    const fileSize = parseInt(meta.data.size || '0', 10);

    const rangeHeader = req.headers['range'];

    if (!rangeHeader) {
      const streamResp = await drive.files.get(
        { fileId, alt: 'media', supportsAllDrives: true },
        { responseType: 'stream' }
      );

      res.setHeader('Content-Type', mimeType);
      res.setHeader('Accept-Ranges', 'bytes');
      res.setHeader('Content-Disposition', 'inline');
      res.setHeader('Cache-Control', 'no-cache');
      if (fileSize > 0) res.setHeader('Content-Length', fileSize);
      res.status(200);

      return streamResp.data.pipe(res);
    }

    let start = 0;
    let end = fileSize > 0 ? fileSize - 1 : undefined;

    const parts = rangeHeader.replace(/bytes=/, '').split('-');
    start = parseInt(parts[0], 10);

    if (parts[1]) {
      end = parseInt(parts[1], 10);
    } else if (fileSize > 0) {
      end = Math.min(start + 2 * 1024 * 1024 - 1, fileSize - 1);
    }

    if (!Number.isFinite(start) || start < 0) start = 0;
    if (!Number.isFinite(end) || end < start) {
      end = fileSize > 0 ? fileSize - 1 : start + 2 * 1024 * 1024 - 1;
    }

    const chunkSize = end - start + 1;

    res.setHeader('Content-Range', fileSize > 0 ? `bytes ${start}-${end}/${fileSize}` : `bytes ${start}-${end}/*`);
    res.setHeader('Accept-Ranges', 'bytes');
    res.setHeader('Content-Length', chunkSize);
    res.setHeader('Content-Type', mimeType);
    res.setHeader('Content-Disposition', 'inline');
    res.setHeader('Cache-Control', 'no-cache');
    res.status(206);

    const streamResp = await drive.files.get(
      { fileId, alt: 'media', supportsAllDrives: true },
      {
        responseType: 'stream',
        headers: { Range: `bytes=${start}-${end}` },
      }
    );

    streamResp.data.pipe(res);
  } catch (err) {
    console.error('ERROR STREAM:', err?.response?.data || err.message || err);
    if (!res.headersSent) {
      return res.status(500).json({
        error: err.message || 'Error al obtener el video',
        detail: err?.response?.data || null,
      });
    }
  }
};