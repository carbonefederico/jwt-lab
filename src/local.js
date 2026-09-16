import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { app } from './app.js';

const envPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../.env');
if (fs.existsSync(envPath)) process.loadEnvFile(envPath);

const port = Number(process.env.PORT || 3000);
app.listen(port, () => {
  console.log(`JWT Lab running at http://localhost:${port}`);
});
