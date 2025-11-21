#!/usr/bin/env python3
import json
import os
import subprocess
import time
import requests
from pathlib import Path
import logging
from datetime import datetime, timedelta

# Configuration
BASE_DIR = "/root/Trufflehog"
DOMAINS_FILE = os.path.join(BASE_DIR, "Domains.txt")
PATS_FILE = os.path.join(BASE_DIR, "PAT.txt")
RESULTS_DIR = os.path.join(BASE_DIR, "trufflehog_results")
VERIFIED_DIR = os.path.join(BASE_DIR, "trufflehog_verified")
COMPLETED_FILE = os.path.join(BASE_DIR, "trufflehog_completed.txt")

# Telegram
TELEGRAM_BOT_TOKEN = "7857988624:AAEMGYHsfGAd2RyeCbLGmEYFq4Q4qfya7Xg"
TELEGRAM_CHAT_ID = "1378430735"

# Settings
MAX_RETRIES_PER_DOMAIN = 3
PAT_COOLDOWN = 300  # 5 minutes
RUN_DURATION = 6 * 60 * 60  # 6 hours in seconds
BREAK_DURATION = 60 * 60  # 1 hour in seconds

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(BASE_DIR, 'trufflehog.log')),
        logging.StreamHandler()
    ]
)

class GitHubScanner:
    def __init__(self):
        self.pats = self._load_pats()
        self.completed_domains = self._load_completed_domains()
        self.rate_limited_pats = {}
        self.current_pat_index = 0

    def _send_telegram_message(self, text: str) -> None:
        """Helper to actually send the Telegram message."""
        try:
            response = requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={
                    "chat_id": TELEGRAM_CHAT_ID,
                    "text": text,
                    "parse_mode": "Markdown",
                    "disable_web_page_preview": True
                },
                timeout=10
            )
            response.raise_for_status()
            logging.info(f"Telegram alert sent successfully")
        except Exception as e:
            logging.error(f"Failed to send Telegram message: {e}")

    def _load_pats(self):
        with open(PATS_FILE, 'r') as f:
            pats = [line.strip() for line in f if line.strip()]
        if not pats:
            raise ValueError("No PATs found.")
        return pats

    def _load_completed_domains(self):
        if not os.path.exists(COMPLETED_FILE):
            return set()
        with open(COMPLETED_FILE, 'r') as f:
            return set(line.strip() for line in f if line.strip())

    def _mark_domain_completed(self, domain):
        self.completed_domains.add(domain)
        with open(COMPLETED_FILE, 'a') as f:
            f.write(f"{domain}\n")

    def _get_available_pat(self):
        now = time.time()
        for _ in range(len(self.pats)):
            pat = self.pats[self.current_pat_index]
            self.current_pat_index = (self.current_pat_index + 1) % len(self.pats)
            if pat in self.rate_limited_pats and self.rate_limited_pats[pat] > now:
                continue
            self.rate_limited_pats.pop(pat, None)
            return pat
        return None

    def _send_telegram_alert(self, domain: str, verified_secrets: list) -> None:
        """Send verified secrets to Telegram with robust handling."""
        if not verified_secrets:
            logging.info("No secrets to alert")
            return

        message = f"🚨 *Verified secrets found in {domain}*:\n"
        count = 0

        for secret in verified_secrets:
            if not isinstance(secret, dict):
                continue  # Skip non-dict entries

            try:
                # Safely extract data with nested .get() and defaults
                detector_name = secret.get("DetectorName", "Unknown Secret")
                
                # Handle nested GitHub data carefully
                gh_data = secret.get("SourceMetadata", {}).get("Data", {}).get("Github", {})
                file_path = gh_data.get("file", "Unknown file")
                commit_url = gh_data.get("link", "")
                
                # Skip if no commit URL (can't provide useful link)
                if not commit_url:
                    continue

                # Build the message for this secret
                count += 1
                message += (
                    f"\n🔍 *{detector_name}*\n"
                    f"📄 `{file_path}`\n"
                    f"🔗 [View Commit]({commit_url})\n"
                )

                # Telegram has a 4096 character limit per message
                if len(message) > 3000:  # Safe buffer
                    self._send_telegram_message(message)
                    message = f"*Continued findings for {domain}:*\n"
                    count = 0

            except Exception as e:
                logging.warning(f"Skipping malformed secret: {str(e)}")
                continue

        if count > 0:
            self._send_telegram_message(message)
        else:
            logging.info("No alertable secrets found (missing required fields)")

    def _run_trufflehog(self, domain, pat):
        cmd = [
            "/root/Trufflehog/trufflehog/trufflehog",
            "github",
            "--org", domain,
            "--token", pat,
            "--json"
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=3600
            )
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            if "403" in (e.stderr or ""):
                self.rate_limited_pats[pat] = time.time() + PAT_COOLDOWN
                return False, "rate_limit"
            return False, e.stderr
        except subprocess.TimeoutExpired:
            return False, "timeout"

    def scan_domain(self, domain):
        logging.info(f"Starting scan for domain: {domain}")
        output_file = os.path.join(RESULTS_DIR, f"{domain}.json")
        verified_file = os.path.join(VERIFIED_DIR, f"{domain}.verified.json")
        attempts = 0
        findings = []

        while attempts < MAX_RETRIES_PER_DOMAIN:
            pat = self._get_available_pat()
            if not pat:
                logging.warning("All PATs are rate-limited. Waiting...")
                time.sleep(PAT_COOLDOWN)
                continue

            logging.info(f"Using PAT ending with ...{pat[-4:]}")
            success, output = self._run_trufflehog(domain, pat)

            if success:
                # Parse JSON output carefully
                valid_entries = 0
                invalid_entries = 0
                
                for line in output.splitlines():
                    try:
                        data = json.loads(line)
                        if isinstance(data, dict):
                            findings.append(data)
                            valid_entries += 1
                        else:
                            logging.debug(f"Skipping non-dict JSON entry: {line[:100]}...")
                            invalid_entries += 1
                    except json.JSONDecodeError:
                        logging.debug(f"Skipping invalid JSON line: {line[:100]}...")
                        invalid_entries += 1
                        continue

                logging.info(f"Parsed {valid_entries} valid entries, skipped {invalid_entries} invalid lines")

                # Save raw results
                with open(output_file, 'w') as f:
                    json.dump(findings, f, indent=2)

                # Filter verified secrets with additional validation
                verified = []
                for entry in findings:
                    if not isinstance(entry, dict):
                        continue
                    if not entry.get("Verified"):
                        continue
                        
                    # Basic validation of required fields
                    gh_data = entry.get("SourceMetadata", {}).get("Data", {}).get("Github", {})
                    if not isinstance(gh_data, dict):
                        continue
                        
                    verified.append(entry)

                if verified:
                    with open(verified_file, 'w') as vf:
                        json.dump(verified, vf, indent=2)
                    logging.info(f"Found {len(verified)} properly formatted verified secrets")
                    self._send_telegram_alert(domain, verified)
                else:
                    logging.info("No properly formatted verified secrets found")

                self._mark_domain_completed(domain)
                return True

            elif output == "rate_limit":
                attempts += 1
                time.sleep(2)
                continue
            else:
                logging.error(f"Scan failed for {domain}: {output}")
                return False

        logging.error(f"Max retries reached for {domain}")
        return False

    def run(self):
        if not os.path.exists(DOMAINS_FILE):
            raise FileNotFoundError(f"{DOMAINS_FILE} not found")
        with open(DOMAINS_FILE, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
        logging.info(f"Loaded {len(domains)} domains and {len(self.pats)} PATs")

        for domain in domains:
            if domain in self.completed_domains:
                logging.info(f"Skipping completed domain: {domain}")
                continue
            
            self.scan_domain(domain)
            time.sleep(5)  # Brief pause between domains

    def run_continuously(self):
        """Run the scanner with scheduled breaks."""
        while True:
            start_time = datetime.now()
            end_time = start_time + timedelta(seconds=RUN_DURATION)
            
            logging.info(f"🚀 Starting scanning cycle. Will run until {end_time}")
            self._send_telegram_message("🔌 Trufflehog scanner started new cycle")
            self.run()  # Normal scanning process
            
            if datetime.now() < end_time:
                # If scanning completed before time was up
                time_remaining = (end_time - datetime.now()).total_seconds()
                logging.info(f"Scanning completed early. Sleeping for {time_remaining:.1f}s")
                time.sleep(time_remaining)
            
            logging.info(f"⏸️ Taking scheduled break for {BREAK_DURATION//60} minutes")
            self._send_telegram_message(
                f"🛑 Scanner pausing for {BREAK_DURATION//60} minute break. "
                f"Resuming at {(datetime.now() + timedelta(seconds=BREAK_DURATION)).strftime('%H:%M')}"
            )
            time.sleep(BREAK_DURATION)

if __name__ == "__main__":
    Path(RESULTS_DIR).mkdir(parents=True, exist_ok=True)
    Path(VERIFIED_DIR).mkdir(parents=True, exist_ok=True)
    
    try:
        scanner = GitHubScanner()
        scanner.run_continuously()  # Start the continuous scanning loop
    except Exception as e:
        logging.error(f"Fatal error: {e}", exc_info=True)
        try:
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={
                    "chat_id": TELEGRAM_CHAT_ID,
                    "text": f"❌ Scanner crashed: {str(e)}",
                    "parse_mode": "Markdown"
                },
                timeout=10
            )
        except Exception as telegram_error:
            logging.error(f"Failed to send crash notification: {telegram_error}")