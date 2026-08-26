# Nullify 웹 — 표준 라이브러리만 쓰므로 pip 의존성 설치 단계가 없다.
FROM python:3.12-slim

WORKDIR /app

# git: remediation/github_pr.py 가 브랜치 생성·패치 커밋에 쓴다.
#      slim 이미지엔 git 이 없어서 web.py 가 import 중 ensure_repo() 에서 죽었다.
# ca-certificates: 사용자 레포를 https 로 clone 할 때 필요
#      (--no-install-recommends 를 쓰면 자동으로 안 딸려온다).
# COPY 앞에 두는 이유: 소스만 바뀐 재배포에서 이 레이어가 캐시돼 빌드가 빨라진다.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY . /app

# 8000: 웹 대시보드 (데모 과녁은 8009 로 프로세스 내부에서 함께 뜬다)
EXPOSE 8000
ENV PYTHONUNBUFFERED=1

# 배포 시 주의: web.py 는 데모용 취약 과녁(vuln_app)을 같이 띄운다 → 개발/데모 전용.
# 실제 서비스에서는 과녁을 빼고, 대상은 authorize.py 의 정책으로만 스캔해야 한다.
# PaaS(Render 등)는 포트를 $PORT 로 주입한다. exec 형식 CMD 는 셸을 안 거쳐 변수 확장이
# 안 되므로 sh -c 로 감싼다. ${PORT:-8000} = 주입되면 그 값, 없으면 8000(로컬 그대로 동작).
# NULLIFY_HOST 는 컨테이너에서만 0.0.0.0 으로 덮어쓴다 — 코드 기본값 127.0.0.1 은 로컬 안전장치.
# exec: python 을 PID 1 로 만들어 재배포 시 SIGTERM 이 셸에 막히지 않게 한다.
CMD ["sh", "-c", "NULLIFY_HOST=0.0.0.0 NULLIFY_PORT=${PORT:-8000} exec python web.py"]
