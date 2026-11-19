import { startServer } from './server.js';

startServer().catch((err) => {
  console.error('Gateway startup failed:', err);
  process.exit(1);
});
