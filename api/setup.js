const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

module.exports = async (req, res) => {
  const { key } = req.query;
  if (key !== process.env.SETUP_KEY) return res.status(403).json({ error: 'No autorizado' });

  try {
    const hash = await bcrypt.hash('lolero1234', 10);
    const { error } = await supabase
      .from('admins')
      .upsert([{ username: 'efra', password_hash: hash }], { onConflict: 'username' });
    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ success: true, message: 'Admin "efra" creado correctamente.' });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
};