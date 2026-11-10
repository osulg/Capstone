import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// 개발: npm run dev (5174) → /api 요청은 Flask 대시보드 서버(5000)로 넘긴다.
//   5173 은 웹 시연 프런트엔드(demo-web/frontend)가 쓰므로 겹치지 않게 고정한다.
// 배포: npm run build → dist/ 를 Flask(server.py)가 그대로 서빙한다.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,
    strictPort: true,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:5000",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
