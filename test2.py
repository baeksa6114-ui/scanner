#!/usr/bin/env python3

"""
test2.py

본인이 소유/관리하는 웹사이트의 공개 영역을 대상으로
API 키/토큰, 소스맵, 위험한 파일, API 응답의 민감정보 등을
점검하는 간단한 보안 스캐너.

사용법:
    pip install requests
    py test2.py https://example.com
"""

import re
import sys
import json
import base64
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    print("requests 모듈이 필요합니다.")
    print("pip install requests")
    sys.exit(1)


TIMEOUT = 10

HEADERS = {
    "User-Agent": "Mozilla/5.0 (SelfSiteSecurityScanner/2.0)"
}


# ---------------------------------------------------------
# 1. 실제로 자주 노출되는 Secret 패턴
# ---------------------------------------------------------

SECRET_PATTERNS = {

    "AWS Access Key":
        r"\bAKIA[0-9A-Z]{16}\b",

    "AWS Secret Key":
        r"(?i)aws[_-]?secret[_-]?access[_-]?key['\"]?\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]",

    "Stripe Live Key":
        r"\bsk_live_[0-9a-zA-Z]{16,}\b",

    "Slack Token":
        r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",

    "Private Key":
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",

    "Generic API Key":
        r"(?i)\b(?:api[_-]?key|apikey)\b['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,100})['\"]",

    "Generic Secret":
        r"(?i)\b(?:secret|client[_-]?secret)\b['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,100})['\"]",

    "Bearer Token":
        r"(?i)\bbearer\s+[A-Za-z0-9_\-\.]{20,200}",

    "DB Connection String":
        r"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql)://[^\s'\"]+",
}


# ---------------------------------------------------------
# 2. 민감 필드
# ---------------------------------------------------------

SENSITIVE_FIELD_NAMES = {
    "password",
    "password_hash",
    "passwd",
    "hashed_password",
    "ssn",
    "social_security_number",
    "card_number",
    "cc_number",
    "cvv",
    "card_cvc",
    "resident_registration_number",
    "phone",
    "phone_number",
    "email",
    "address",
    "salt",
    "refresh_token",
    "access_token",
    "session_token",
    "service_role"
}


# ---------------------------------------------------------
# 3. 점검할 위험 경로
# ---------------------------------------------------------

RISKY_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/config.json",
    "/firebase.json",
    "/.git/config",
    "/.git/HEAD",
    "/backup.sql",
    "/db.sql",
    "/dump.sql",
    "/wp-config.php.bak",

    # API 후보
    "/api/users",
    "/api/user",
    "/api/members",
    "/api/member",
    "/api/users/list",
    "/api/members/list",
]


# ---------------------------------------------------------
# HTTP
# ---------------------------------------------------------

def fetch(url):
    try:
        return requests.get(
            url,
            headers=HEADERS,
            timeout=TIMEOUT,
            allow_redirects=True
        )
    except requests.RequestException:
        return None


# ---------------------------------------------------------
# 실제 JWT인지 확인
# ---------------------------------------------------------

def looks_like_real_jwt(value):
    """
    단순히 eyJ... 문자열이라고 JWT로 판단하지 않고
    header.payload.signature 3부분 구조인지 확인한다.
    """

    value = value.strip()

    parts = value.split(".")

    if len(parts) != 3:
        return False

    try:
        # JWT header/payload는 Base64URL JSON이어야 함
        for part in parts[:2]:

            # padding 복구
            padded = part + "=" * (-len(part) % 4)

            decoded = base64.urlsafe_b64decode(
                padded.encode()
            ).decode("utf-8")

            obj = json.loads(decoded)

            if not isinstance(obj, dict):
                return False

        return True

    except Exception:
        return False


# ---------------------------------------------------------
# 텍스트에서 Secret 검색
# ---------------------------------------------------------

def scan_text_for_secrets(text, source_label, findings):

    # 너무 긴 바이너리/압축 데이터는 건너뜀
    if not text:
        return

    for name, pattern in SECRET_PATTERNS.items():

        for match in re.finditer(pattern, text):

            snippet = match.group(0)

            masked = (
                snippet[:8] + "..." + snippet[-4:]
                if len(snippet) > 12
                else snippet
            )

            findings.append({
                "type": "secret_pattern",
                "pattern": name,
                "source": source_label,
                "masked_match": masked,
            })


# ---------------------------------------------------------
# JWT 탐지
# ---------------------------------------------------------

def scan_for_real_jwt(text, source_label, findings):

    # JWT 후보만 찾음
    candidates = re.findall(
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        text
    )

    for token in candidates:

        if looks_like_real_jwt(token):

            findings.append({
                "type": "jwt_exposed",
                "source": source_label,
                "masked_match": token[:10] + "..." + token[-6:],
            })


# ---------------------------------------------------------
# JSON에서 민감 필드 검색
# ---------------------------------------------------------

def scan_json_for_sensitive_fields(
    obj,
    source_label,
    findings,
    path=""
):

    if isinstance(obj, dict):

        for key, value in obj.items():

            full_path = (
                f"{path}.{key}"
                if path
                else key
            )

            if key.lower() in SENSITIVE_FIELD_NAMES:

                findings.append({
                    "type": "sensitive_field",
                    "field": full_path,
                    "source": source_label,
                })

            scan_json_for_sensitive_fields(
                value,
                source_label,
                findings,
                full_path
            )

    elif isinstance(obj, list):

        for index, item in enumerate(obj):

            scan_json_for_sensitive_fields(
                item,
                source_label,
                findings,
                f"{path}[{index}]"
            )


# ---------------------------------------------------------
# API 응답이 실제 JSON인지 확인
# ---------------------------------------------------------

def is_json_response(resp):

    content_type = (
        resp.headers.get("Content-Type", "")
        .lower()
    )

    if "application/json" in content_type:
        return True

    # 서버가 Content-Type을 잘못 지정하는 경우 대비
    try:
        json.loads(resp.text)
        return True
    except Exception:
        return False


# ---------------------------------------------------------
# 위험 경로 검사
# ---------------------------------------------------------

def check_risky_paths(base_url, findings):

    parsed = urllib.parse.urlparse(base_url)

    origin = (
        f"{parsed.scheme}://{parsed.netloc}"
    )

    with ThreadPoolExecutor(max_workers=8) as executor:

        futures = {
            executor.submit(
                fetch,
                origin + path
            ): path
            for path in RISKY_PATHS
        }

        for future in as_completed(futures):

            path = futures[future]

            try:
                resp = future.result()
            except Exception:
                continue

            if resp is None:
                continue

            # -------------------------------------------------
            # 1. 환경설정/백업 파일
            # -------------------------------------------------

            if path in {
                "/.env",
                "/.env.local",
                "/.env.production",
                "/.git/config",
                "/.git/HEAD",
                "/backup.sql",
                "/db.sql",
                "/dump.sql",
                "/wp-config.php.bak",
            }:

                if resp.status_code == 200:

                    findings.append({
                        "type": "risky_file_accessible",
                        "path": path,
                        "status": resp.status_code,
                        "size_bytes": len(resp.content),
                    })

                continue

            # -------------------------------------------------
            # 2. API 경로
            # -------------------------------------------------

            if path.startswith("/api/"):

                if resp.status_code != 200:
                    continue

                # 핵심 개선:
                # HTML이면 API 노출로 판단하지 않는다.
                if not is_json_response(resp):
                    continue

                try:
                    data = resp.json()
                except Exception:
                    continue

                # JSON 응답이면 실제 민감 필드를 검사
                before = len(findings)

                scan_json_for_sensitive_fields(
                    data,
                    origin + path,
                    findings
                )

                # 민감 필드가 실제로 발견된 경우에만 경고
                if len(findings) > before:

                    findings.append({
                        "type": "api_sensitive_data",
                        "path": path,
                        "status": resp.status_code,
                        "size_bytes": len(resp.content),
                    })

                continue


# ---------------------------------------------------------
# HTML에서 JS/CSS URL 추출
# ---------------------------------------------------------

def extract_asset_urls(base_url, html):

    urls = set()

    pattern = (
        r"""(?:src|href)=['"]([^'"]+\.(?:js|css|js\.map)(?:\?[^'"]*)?)['"]"""
    )

    for match in re.finditer(
        pattern,
        html,
        re.I
    ):

        urls.add(
            urllib.parse.urljoin(
                base_url,
                match.group(1)
            )
        )

    return urls


# ---------------------------------------------------------
# 페이지 검사
# ---------------------------------------------------------

def scan_page(url):

    findings = []

    resp = fetch(url)

    if resp is None:

        print(f"[!] 접속 실패: {url}")

        return findings

    html = resp.text

    # -----------------------------------------------------
    # HTML 자체
    # -----------------------------------------------------

    scan_text_for_secrets(
        html,
        f"{url} (inline HTML)",
        findings
    )

    scan_for_real_jwt(
        html,
        f"{url} (inline HTML)",
        findings
    )

    # -----------------------------------------------------
    # JS/CSS
    # -----------------------------------------------------

    asset_urls = extract_asset_urls(
        url,
        html
    )

    for asset_url in asset_urls:

        asset_resp = fetch(asset_url)

        if asset_resp is None:
            continue

        scan_text_for_secrets(
            asset_resp.text,
            asset_url,
            findings
        )

        scan_for_real_jwt(
            asset_resp.text,
            asset_url,
            findings
        )

        # JS source map
        if re.search(
            r"\.js(?:\?|$)",
            asset_url,
            re.I
        ):

            map_url = (
                asset_url.split("?")[0]
                + ".map"
            )

            map_resp = fetch(map_url)

            if (
                map_resp is not None
                and map_resp.status_code == 200
            ):

                findings.append({
                    "type": "sourcemap_exposed",
                    "url": map_url,
                    "size_bytes": len(
                        map_resp.content
                    ),
                })

    # -----------------------------------------------------
    # embedded JSON
    # -----------------------------------------------------

    pattern = (
        r'<script[^>]+type=["\']application/json["\'][^>]*>'
        r'(.*?)'
        r'</script>'
    )

    for match in re.finditer(
        pattern,
        html,
        re.S | re.I
    ):

        try:

            data = json.loads(
                match.group(1)
            )

            scan_json_for_sensitive_fields(
                data,
                f"{url} (embedded JSON)",
                findings
            )

        except (
            json.JSONDecodeError,
            ValueError
        ):
            pass

    # -----------------------------------------------------
    # 위험 경로
    # -----------------------------------------------------

    check_risky_paths(
        url,
        findings
    )

    return findings


# ---------------------------------------------------------
# 결과 출력
# ---------------------------------------------------------

def print_report(url, findings):

    print()
    print("=" * 60)
    print(f"대상: {url}")
    print("=" * 60)

    if not findings:

        print(
            "  발견된 이슈 없음 "
            "(패턴 기반 점검이므로 완전한 보장은 아님)"
        )

        return

    for finding in findings:

        finding_type = finding["type"]

        if finding_type == "secret_pattern":

            print(
                f"  [경고] Secret 의심 패턴 "
                f"'{finding['pattern']}' 발견 → "
                f"{finding['source']} "
                f"({finding['masked_match']})"
            )

        elif finding_type == "jwt_exposed":

            print(
                f"  [경고] 실제 JWT 형태의 토큰 발견 → "
                f"{finding['source']} "
                f"({finding['masked_match']})"
            )

        elif finding_type == "sensitive_field":

            print(
                f"  [주의] 민감 필드 발견 → "
                f"{finding['field']} "
                f"({finding['source']})"
            )

        elif finding_type == "api_sensitive_data":

            print(
                f"  [위험] API 응답에서 민감정보 필드 발견 → "
                f"{finding['path']} "
                f"({finding['size_bytes']} bytes)"
            )

        elif finding_type == "sourcemap_exposed":

            print(
                f"  [주의] Source Map 접근 가능 → "
                f"{finding['url']} "
                f"({finding['size_bytes']} bytes)"
            )

        elif finding_type == "risky_file_accessible":

            print(
                f"  [위험] 민감 파일 접근 가능 → "
                f"{finding['path']} "
                f"(status={finding['status']}, "
                f"{finding['size_bytes']} bytes)"
            )


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():

    if len(sys.argv) < 2:

        print(
            "사용법: "
            "python3 site_secret_scanner.py "
            "https://example.com"
        )

        sys.exit(1)

    urls = sys.argv[1:]

    print(
        "본인이 소유/관리하는 사이트에만 사용하세요."
    )

    for url in urls:

        findings = scan_page(url)

        print_report(
            url,
            findings
        )


if __name__ == "__main__":
    main()