# Nullify 웹 — 표준 라이브러리만 쓰므로 의존성 설치 단계가 없다.
FROM python:3.12-slim

WORKDIR /app
COPY . /app

# 8000: 웹 대시보드 (데모 과녁은 8009 로 프로세스 내부에서 함께 뜬다)
EXPOSE 8000
ENV PYTHONUNBUFFERED=1

# 배포 시 주의: web.py 는 데모용 취약 과녁(vuln_app)을 같이 띄운다 → 개발/데모 전용.
# 실제 서비스에서는 과녁을 빼고, 대상은 authorize.py 의 정책으로만 스캔해야 한다.
CMD ["python", "web.py"]
