"""
알림(notification) — 재검증에서 '리그레션(새로 생김)'이 감지되면 알린다.

정직한 경계:
  - 기본은 '로컬 알림 로그(DB)' — 완전히 자족적이고 테스트 가능.
  - 외부 전송(Slack 등)은 NULLIFY_WEBHOOK 환경변수가 있을 때만 발동.
    비밀(웹훅 URL)은 이 코드가 읽기만 하고 로그/반환에 담지 않는다.
  - 웹훅이 없으면 아무 외부 요청도 하지 않는다.
"""
import os
import json
import urllib.request

import infra.store as store


def build_alert(target, scan_id, compare):
    regs = compare.get("new", [])
    message = "리그레션 %d건 @ %s (스캔 #%s): %s" % (
        len(regs), target, scan_id, ", ".join(regs))
    return {"level": "regression", "target": target, "scan_id": scan_id,
            "message": message, "regressions": regs}


def _post_webhook(url, alert):
    body = json.dumps({"text": "[Nullify] " + alert["message"]}).encode("utf-8")  # Slack 호환
    req = urllib.request.Request(url, data=body, headers={"content-type": "application/json"})
    urllib.request.urlopen(req, timeout=5).read()


def notify(alert, user_id=0):
    """알림을 로컬 로그에 저장하고, 웹훅이 설정돼 있으면 전송 시도."""
    nid = store.save_notification(alert["target"], alert["scan_id"],
                                  alert["level"], alert["message"], user_id)
    url = os.environ.get("NULLIFY_WEBHOOK")
    sent = False
    if url:
        try:
            _post_webhook(url, alert)
            sent = True
        except Exception:
            sent = False
    return {"id": nid, "webhook_configured": bool(url), "webhook_sent": sent}
