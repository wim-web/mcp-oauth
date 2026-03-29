import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** @type {import('next').NextConfig} */
export default {
  experimental: {
    externalDir: true,
  },
  turbopack: {
    root: path.join(__dirname, '..'),
  },
  async rewrites() {
    return [{ source: '/callback', destination: '/' }];
  },
};
