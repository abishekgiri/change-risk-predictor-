import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
    plugins: [react()],
    root: 'static/admin',
    base: './',
    build: {
        outDir: '../../dist/admin',
        emptyOutDir: true,
    },
    server: {
        port: 3000
    }
});
