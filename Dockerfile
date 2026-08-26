# ─────────────────────────────────────────────────────────────────────
# 1단계: React(Vite) 프론트엔드 + Express 서버 번들 빌드
# ─────────────────────────────────────────────────────────────────────
FROM node:22-slim AS webbuild
WORKDIR /build

# package*.json 만 먼저 복사하면 소스만 바뀐 재배포에서 npm ci 레이어가 캐시된다.
COPY unknown-security-scanner/package.json unknown-security-scanner/package-lock.json ./
RUN npm ci

COPY unknown-security-scanner/ ./
# vite build → dist/(정적 파일), esbuild → dist/server.cjs
RUN npm run build
# --packages=external 로 번들해서 런타임에 node_modules 가 필요하다.
# 빌드 도구(vite·esbuild·typescript)는 이제 불필요하므로 쳐낸다.
RUN npm prune --omit=dev

# ─────────────────────────────────────────────────────────────────────
# 2단계: 실행 이미지 — 파이썬 스캔 엔진 + Node 웹 서버를 한 컨테이너에
# ─────────────────────────────────────────────────────────────────────
FROM python:3.12-slim
WORKDIR /app

# git: remediation/github_pr.py 가 브랜치 생성·패치 커밋에 쓴다(없으면 web.py 가 import 중 죽음).
# ca-certificates: https 로 사용자 레포를 clone 할 때 필요.
# libstdc++6: 아래에서 복사해 오는 node 바이너리가 링크하는 런타임.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates libstdc++6 \
 && rm -rf /var/lib/apt/lists/*

# node 바이너리만 가져온다. 두 이미지 모두 Debian bookworm 기반이라 호환된다.
# (node 이미지를 베이스로 삼고 python 을 apt 로 넣으면 3.11 이 깔려서 3.12 를 못 쓴다.)
COPY --from=webbuild /usr/local/bin/node /usr/local/bin/node

COPY . /app
COPY --from=webbuild /build/dist         /app/unknown-security-scanner/dist
COPY --from=webbuild /build/node_modules /app/unknown-security-scanner/node_modules

# production 이어야 server.ts 가 Vite 개발 미들웨어 대신 dist/ 를 정적 서빙한다.
ENV NODE_ENV=production \
    PYTHONUNBUFFERED=1

EXPOSE 3000

# 두 프로세스를 함께 띄운다:
#   - 파이썬 엔진: 127.0.0.1:8000 (컨테이너 내부 전용. 외부 노출은 Express 프록시로만)
#   - Express:     $PORT (Render 가 주입) — SPA 서빙 + /nullify/* 프록시 + Gemini 챗
# exec 로 node 를 PID 1 로 만들어 재배포 시 SIGTERM 이 제대로 전달되게 한다.
# 엔진이 죽으면 /healthz 가 503 을 내므로 배포 실패로 즉시 드러난다.
CMD ["sh", "-c", "cd /app && NULLIFY_HOST=127.0.0.1 NULLIFY_PORT=8000 python web.py & cd /app/unknown-security-scanner && exec node dist/server.cjs"]
