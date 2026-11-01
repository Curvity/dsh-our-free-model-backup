#!/usr/bin/env python3
"""OFM Automated Watchdog & Forensic Metadata Mirror (Anti-Spam & State-Safe Edition).

Fixes applied:
1. Sanitizes all @username mentions into `@username` to prevent triggering external user notifications or GitHub spam flags.
2. Synchronizes the mirror issue's open/closed state with upstream so closed issues do NOT trigger infinite comments every 5 minutes.
3. Enforces a 2.5-second sleep between write API calls and caps new mirror creations at MAX_CREATE_PER_RUN = 200 per run to stay well below GitHub Secondary Rate Limits.
4. Tracks body SHA256 hashes in an embedded HTML marker to detect and log upstream body edits.
"""

import os
import re
import sys
import time
import json
import hashlib
import subprocess
import urllib.request
import urllib.error
from datetime import datetime, timezone

UPSTREAM_REPO = os.environ.get("UPSTREAM_REPO", "Ebony-Vinyl/dsh-our-free-model")
GH_TOKEN = os.environ.get("GH_TOKEN", "")
MAX_CREATE_PER_RUN = 200
WRITE_SLEEP_SECONDS = 2.5


def sanitize_mentions(text: str) -> str:
    """Super-safe mention sanitizer: wraps @mentions in backticks AND injects zero-width space \u200b.
    This guarantees 100% immunity against GitHub mention notifications, web push, and email alerts.
    """
    if not text:
        return ""
    def repl(m):
        uname = m.group(1)
        return f"`@{chr(0x200b)}{uname}`"
    return re.sub(r'(?<![`\w])@([a-zA-Z0-9_-]+)', repl, text)


def body_sha256(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()[:16]


def gh_api_request(endpoint, method="GET", data=None, max_retries=3):
    url = f"https://api.github.com/{endpoint.lstrip('/')}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "OFM-Watchdog-Archiver/1.1",
    }
    if GH_TOKEN:
        headers["Authorization"] = f"Bearer {GH_TOKEN}"

    req_body = json.dumps(data).encode("utf-8") if data else None

    for attempt in range(1, max_retries + 1):
        try:
            req = urllib.request.Request(url, data=req_body, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=30) as resp:
                content = resp.read().decode("utf-8")
                return json.loads(content) if content else {}
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            err_text = e.read().decode("utf-8", errors="replace")
            print(f"[API Error] {method} {url} -> {e.code}: {err_text}", file=sys.stderr)
            if e.code in (403, 429):
                print("[Rate Limit] Secondary rate limit hit; halting gracefully for next cycle.", file=sys.stderr)
                sys.exit(0)
            if attempt == max_retries:
                raise
            time.sleep(2 * attempt)
        except Exception as e:
            print(f"[Network Warn] {method} {url} attempt {attempt}/{max_retries} failed ({e}), retrying in {2 * attempt}s...", file=sys.stderr)
            if attempt == max_retries:
                # 终极保底：通过本机官方 gh api CLI 执行
                try:
                    gh_cmd = ["gh", "api", endpoint.lstrip("/"), "-X", method]
                    if data:
                        p = subprocess.run(gh_cmd, input=json.dumps(data), capture_output=True, text=True, encoding="utf-8")
                    else:
                        p = subprocess.run(gh_cmd, capture_output=True, text=True, encoding="utf-8")
                    if p.returncode == 0 and p.stdout.strip():
                        return json.loads(p.stdout)
                except Exception as ex:
                    print(f"[GH Fallback Error] {ex}", file=sys.stderr)
                raise
            time.sleep(2 * attempt)


def get_current_repo():
    env_repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    if env_repo:
        return env_repo
    cmd = ["gh", "repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0 and res.stdout.strip():
        return res.stdout.strip()
    return ""


def list_mirrored_issues(target_repo):
    mirrored = {}
    page = 1
    while page <= 10:
        data = gh_api_request(f"repos/{target_repo}/issues?state=all&per_page=100&page={page}")
        if not data:
            break
        for item in data:
            if "pull_request" in item:
                continue
            title = item.get("title", "")
            m = re.search(r'^\[mirrored\]\s*#(\d+):', title)
            if m:
                mirrored[int(m.group(1))] = item
        if len(data) < 100:
            break
        page += 1
    return mirrored


def build_mirror_body(u_issue):
    u_num = u_issue["number"]
    u_author = u_issue.get("user", {}).get("login", "unknown")
    u_state = u_issue.get("state", "open")
    u_html_url = u_issue.get("html_url", "")
    raw_body = u_issue.get("body", "") or "*No body description provided.*"
    safe_body = sanitize_mentions(raw_body)
    b_hash = body_sha256(raw_body)
    is_pr = "pull_request" in u_issue
    kind = "Pull Request" if is_pr else "Issue"
    now_iso = datetime.now(timezone.utc).isoformat()

    meta_json = json.dumps({"u_num": u_num, "state": u_state, "body_hash": b_hash})
    return f"""<!-- ofm-backup-meta: {meta_json} -->
> **Forensic Mirror Record**  
> **Original Upstream {kind}**: [#{u_num} on {UPSTREAM_REPO}]({u_html_url})  
> **Author**: `@{chr(0x200b)}{u_author}` | **Upstream State**: `{u_state}` | **Synced At**: `{now_iso}`  

---

### Upstream Content:

{safe_body}
"""


def parse_mirror_meta(m_issue):
    body = m_issue.get("body", "") or ""
    m = re.search(r'<!--\s*ofm-backup-meta:\s*(\{.*?\})\s*-->', body)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass
    return {}


def mirror_issue(target_repo, u_issue):
    u_num = u_issue["number"]
    u_title = sanitize_mentions(u_issue.get("title", ""))
    u_state = u_issue.get("state", "open")
    title = f"[mirrored] #{u_num}: {u_title}"[:250]
    body = build_mirror_body(u_issue)

    # 熔断守卫：确保发送前绝对没有任何裸 @username 能够穿透
    leaks = re.findall(r'(?<![`\w])@[a-zA-Z0-9_-]+', title + " " + body)
    if leaks:
        raise RuntimeError(f"FATAL: Mention leak detected before API dispatch: {leaks}!")
    print(f"Creating mirror for upstream #{u_num} (Safe Mention Check Passed)...")
    created = gh_api_request(f"repos/{target_repo}/issues", method="POST", data={"title": title, "body": body})
    time.sleep(WRITE_SLEEP_SECONDS)

    # If upstream item is already closed, close the mirror issue immediately so states match
    if created and u_state == "closed":
        m_num = created["number"]
        gh_api_request(f"repos/{target_repo}/issues/{m_num}", method="PATCH", data={"state": "closed"})
        time.sleep(WRITE_SLEEP_SECONDS)
    return created


def record_change(target_repo, target_issue_num, event_type, details, patch_data=None):
    ts = datetime.now(timezone.utc).isoformat()
    safe_details = sanitize_mentions(details)
    comment_body = f"""<!-- ofm-backup-event at {ts} -->
### 🚨 Watchdog Anomaly Detected: {event_type}

- **Detection Time**: `{ts}`
- **Upstream Repository**: `{UPSTREAM_REPO}`

{safe_details}
"""
    gh_api_request(f"repos/{target_repo}/issues/{target_issue_num}/comments", method="POST", data={"body": comment_body})
    time.sleep(WRITE_SLEEP_SECONDS)
    if patch_data:
        gh_api_request(f"repos/{target_repo}/issues/{target_issue_num}", method="PATCH", data=patch_data)
        time.sleep(WRITE_SLEEP_SECONDS)
    print(f"Recorded event '{event_type}' on mirror issue #{target_issue_num}")


def main():
    target_repo = get_current_repo()
    if not target_repo:
        print("Target repository not specified, exiting.")
        sys.exit(1)

    print(f"Starting Watchdog Metadata Mirror: {UPSTREAM_REPO} -> {target_repo}")
    mirrored = list_mirrored_issues(target_repo)
    print(f"Found {len(mirrored)} existing mirrored issues in watchdog.")

    page = 1
    created_count = 0
    while created_count < MAX_CREATE_PER_RUN and page <= 10:
        upstream_items = gh_api_request(f"repos/{UPSTREAM_REPO}/issues?state=all&sort=updated&direction=desc&per_page=100&page={page}")
        if upstream_items is None:
            print("Upstream 404 or unreachable. Halting metadata sync.")
            return
        if not upstream_items:
            break

        for item in upstream_items:
            if created_count >= MAX_CREATE_PER_RUN:
                break
            u_num = item["number"]
            u_state = item.get("state", "open")
            u_title = sanitize_mentions(item.get("title", ""))
            u_raw_body = item.get("body", "") or "*No body description provided.*"
            u_hash = body_sha256(u_raw_body)
            expected_title = f"[mirrored] #{u_num}: {u_title}"[:250]

            if u_num not in mirrored:
                print(f"[{created_count + 1}/{MAX_CREATE_PER_RUN}] ", end="")
                new_mirror = mirror_issue(target_repo, item)
                if new_mirror:
                    mirrored[u_num] = new_mirror
                    created_count += 1
        else:
            m_issue = mirrored[u_num]
            m_target_num = m_issue["number"]
            m_state = m_issue.get("state", "open")
            m_title = m_issue.get("title", "")
            meta = parse_mirror_meta(m_issue)
            old_hash = meta.get("body_hash")

            # 1. Check state change (and sync mirror state so it only fires ONCE!)
            if u_state != m_state:
                record_change(
                    target_repo,
                    m_target_num,
                    "State Alteration",
                    f"Upstream status changed from `{m_state}` to `{u_state}`.",
                    patch_data={"state": u_state, "body": build_mirror_body(item)},
                )

            # 2. Check title edit (and update mirror title so it only fires ONCE!)
            if m_title != expected_title:
                record_change(
                    target_repo,
                    m_target_num,
                    "Title Renamed",
                    f"Upstream title was edited.\n\n- **Previous Mirror Title**: `{m_title}`\n- **New Upstream Title**: `{u_title}`",
                    patch_data={"title": expected_title, "body": build_mirror_body(item)},
                )

            # 3. Check body edit (and update mirror body hash so it only fires ONCE!)
            elif old_hash and old_hash != u_hash:
                record_change(
                    target_repo,
                    m_target_num,
                    "Body Edited",
                    f"Upstream body text was modified (SHA256 `{old_hash}` -> `{u_hash}`).\n\n### New Upstream Body:\n\n{sanitize_mentions(u_raw_body)}",
                    patch_data={"body": build_mirror_body(item)},
                )

        if len(upstream_items) < 100:
            break
        page += 1

    print(f"Watchdog metadata sync cycle completed (created {created_count} new mirrors).")


if __name__ == "__main__":
    main()
