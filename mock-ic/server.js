const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Serve static files
app.use(express.static(__dirname));

// Endpoint to get registry data
app.get('/get_nodes', (req, res) => {
  try {
    const registryData = JSON.parse(fs.readFileSync(path.join(__dirname, 'registry.json'), 'utf8'));
    res.json(registryData);
  } catch (error) {
    console.error('Error reading registry data:', error);
    res.status(500).json({ error: 'Failed to read registry data' });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Mock IC Registry server running on port ${PORT}`);
  console.log(`Open http://localhost:${PORT} in your browser to view the dashboard`);
}); 