#!/usr/bin/env python3
"""
site_secret_scanner.py
-----------------------
내가 만든(소유/관리 권한이 있는) 웹사이트를 대상으로,
개발자도구(Network/Sources)에서 노출될 수 있는
API 키, 시크릿, 소스맵, 과도한 응답 필드 등을 점검하는 스크립트.

※ 반드시 본인이 소유/관리하는 사이트에만 사용하세요.

사용법:
    pip install requests --break-system-packages
    python3 site_secret_scanner.py https://내사이트.com

여러 페이지를 함께 점검하고 싶으면:
    python3 site_secret_scanner.py https://내사이트.com https://내사이트.com/login
"""

import re
import sys
import json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    print("requests 모듈이 필요합니다: pip install requests --break-system-packages")
    sys.exit(1)

TIMEOUT = 10
HEADERS = {"User-Agent": "Mozilla/5.0 (SelfSiteSecurityScanner/1.0)"}

# 1) 흔히 하드코딩되어 유출되는 키/시크릿 패턴
SECRET_PATTERNS = {
    "Generic API Key": r"""(?i)(api[_-]?key|apikey)['"]?\s*[:=]\s*['"]([A-Za-z0-9_\-]{16,64})['"]""",
    "Generic Secret": r"""(?i)(secret|client[_-]?secret)['"]?\s*[:=]\s*['"]([A-Za-z0-9_\-]{16,64})['"]""",
    "Bearer/Access Token": r"""(?i)(access[_-]?token|bearer)['"]?\s*[:=]\s*['"]([A-Za-z0-9_\-\.]{16,128})['"]""",
    "AWS Access Key": r"""AKIA[0-9A-Z]{16}""",
    "AWS Secret Key": r"""(?i)aws_secret_access_key['"]?\s*[:=]\s*['"]([A-Za-z0-9/+=]{40})['"]""",
    "Firebase Config Key": r"""(?i)firebase(Config)?['"]?\s*[:=]\s*\{[^}]*apiKey['"]?\s*[:=]\s*['"]([A-Za-z0-9_\-]{20,60})['"]""",
    "Stripe Live Key": r"""sk_live_[0-9a-zA-Z]{16,}""",
    "Slack Token": r"""xox[baprs]-[0-9A-Za-z-]{10,}""",
    "Private Key Block": r"""-----BEGIN (RSA |EC |)PRIVATE KEY-----""",
    "JWT-like Token": r"""eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}""",
    "Generic Password Field": r"""(?i)(password|passwd|pwd)['"]?\s*[:=]\s*['"]([^'"\s]{6,64})['"]""",
    "DB Connection String": r"""(?i)(mongodb(\+srv)?|postgres(ql)?|mysql):\/\/[^\s'"]+""",
}

# 2) 응답 JSON에서 과도하게 노출되면 위험한 필드명
SENSITIVE_FIELD_NAMES = {
    "password", "password_hash", "passwd", "hashed_password",
    "ssn", "social_security_number", "card_number", "cc_number",
    "cvv", "card_cvc", "resident_registration_number",
    "phone", "phone_number", "email", "address", "salt",
    "refresh_token", "access_token", "session_token",
}

# 3) 소스맵/백업/설정 파일 등 접근 가능하면 위험한 경로
RISKY_PATHS = [
    "/.env", "/.env.local", "/.env.production",
    "/config.json", "/firebase.json",
    "/.git/config", "/.git/HEAD",
    "/backup.sql", "/db.sql", "/dump.sql",
    "/wp-config.php.bak",
    "/.DS_Store",
    "/admin", "/admin.json",
    "/api/users", "/api/user/list", "/api/members",
]


def fetch(url):
    try:
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
        return resp
    except requests.RequestException as e:
        return None


def extract_asset_urls(base_url, html):
    """HTML에서 <script src=...>, <link href=...> 등의 정적 자산 URL 추출"""
    urls = set()
    for m in re.finditer(r"""(?:src|href)=['"]([^'"]+\.(?:js|css|js\.map))['"]""", html, re.I):
        urls.add(urllib.parse.urljoin(base_url, m.group(1)))
    # 인라인 script 블록도 검사 대상에 포함하기 위해 표시
    return urls


def scan_text_for_secrets(text, source_label, findings):
    for name, pattern in SECRET_PATTERNS.items():
        for m in re.finditer(pattern, text):
            snippet = m.group(0)
            masked = snippet[:6] + "..." + snippet[-4:] if len(snippet) > 12 else snippet
            findings.append({
                "type": "secret_pattern",
                "pattern": name,
                "source": source_label,
                "masked_match": masked,
            })


def scan_json_for_sensitive_fields(obj, source_label, findings, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_path = f"{path}.{k}" if path else k
            if k.lower() in SENSITIVE_FIELD_NAMES:
                findings.append({
                    "type": "sensitive_field",
                    "field": full_path,
                    "source": source_label,
                })
            scan_json_for_sensitive_fields(v, source_label, findings, full_path)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            scan_json_for_sensitive_fields(item, source_label, findings, f"{path}[{i}]")


def check_risky_paths(base_url, findings):
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(fetch, origin + p): p for p in RISKY_PATHS}
        for fut in as_completed(futures):
            path = futures[fut]
            resp = fut.result()
            if resp is not None and resp.status_code == 200 and len(resp.content) > 0:
                findings.append({
                    "type": "risky_path_accessible",
                    "path": path,
                    "status": resp.status_code,
                    "size_bytes": len(resp.content),
                })


def scan_page(url):
    findings = []
    resp = fetch(url)
    if resp is None:
        print(f"[!] 접속 실패: {url}")
        return findings

    html = resp.text
    scan_text_for_secrets(html, f"{url} (inline HTML)", findings)

    # JS/CSS/소스맵 등 정적 자산 수집 및 검사
    asset_urls = extract_asset_urls(url, html)
    for asset_url in asset_urls:
        a_resp = fetch(asset_url)
        if a_resp is None:
            continue
        scan_text_for_secrets(a_resp.text, asset_url, findings)
        if asset_url.endswith(".js"):
            # 소스맵 파일이 실제로 존재하는지 확인
            map_url = asset_url + ".map"
            m_resp = fetch(map_url)
            if m_resp is not None and m_resp.status_code == 200:
                findings.append({
                    "type": "sourcemap_exposed",
                    "url": map_url,
                })

    # 페이지 내 <script type="application/json"> 같은 임베디드 JSON도 확인
    for m in re.finditer(r"""<script[^>]+type=["']application/json["'][^>]*>(.*?)</script>""", html, re.S | re.I):
        try:
            data = json.loads(m.group(1))
            scan_json_for_sensitive_fields(data, f"{url} (embedded JSON)", findings)
        except (json.JSONDecodeError, ValueError):
            pass

    check_risky_paths(url, findings)
    return findings


def print_report(url, findings):
    print(f"\n{'='*60}")
    print(f"대상: {url}")
    print(f"{'='*60}")
    if not findings:
        print("  발견된 이슈 없음 (패턴 기반 점검이므로 완전한 보장은 아님)")
        return
    for f in findings:
        if f["type"] == "secret_pattern":
            print(f"  [경고] 시크릿 의심 패턴 '{f['pattern']}' 발견 → {f['source']} ({f['masked_match']})")
        elif f["type"] == "sensitive_field":
            print(f"  [주의] 민감 필드명 노출 → {f['field']} ({f['source']})")
        elif f["type"] == "sourcemap_exposed":
            print(f"  [주의] 소스맵 파일 접근 가능 → {f['url']}")
        elif f["type"] == "risky_path_accessible":
            print(f"  [경고] 위험 경로 접근 가능 → {f['path']} (status={f['status']}, {f['size_bytes']} bytes)")


def main():
    if len(sys.argv) < 2:
        print("사용법: python3 site_secret_scanner.py https://내사이트.com [추가 페이지 URL ...]")
        sys.exit(1)

    urls = sys.argv[1:]
    print("본인이 소유/관리하는 사이트에만 사용하세요.")
    for url in urls:
        findings = scan_page(url)
        print_report(url, findings)


if __name__ == "__main__":
    main()
