import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
    plugins: [react()],
    root: 'static/panel',
    base: './',
    build: {
        outDir: '../../dist/panel',
        emptyOutDir: true,
    },
    server: {
        port: 3001
    }
});
