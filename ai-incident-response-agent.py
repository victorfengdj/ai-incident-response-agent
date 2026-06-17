#!/usr/bin/python3
import boto3
import json
import datetime
import subprocess
import os
import requests
from botocore.exceptions import ClientError
from dotenv import load_dotenv

# Load VIRUSTOTAL_API_KEY and any other secrets from a local .env file so the
# script works without manually exporting variables in the shell.
load_dotenv()

# --- 1. Configuration & Persona ---
# Ensure AWS credentials are set via 'aws configure' or IAM Roles
client = boto3.client("bedrock-runtime", region_name="us-east-1")
# Cross-region inference profile required for on-demand invocation of Haiku 4.5.
model_id = "us.anthropic.claude-haiku-4-5-20251001-v1:0"

SYSTEM_PROMPT = """
You are a Tier 3 Cybersecurity Incident Response Architect. You are investigating
potential attacks originating from the Internet, hitting a DMZ Web Server,
and potentially moving laterally to an Internal Oracle Database.

For every analysis:
1. Identify the MITRE ATT&CK Tactic and Technique ID.
2. Provide a 'Confidence Score' (Low/Med/High).
3. Provide a 'Forensic Command' (grep, journalctl, ps, netstat, aureport) for the Linux hosts.
4. Provide a 'Database Query' (SQL) for Oracle Unified Auditing if applicable.
5. Provide a 'Business Case' if a security gap is identified.

Keep your tone professional, technical, and concise.
"""

# Full conversation history is passed on every call so the model retains context
# across the entire investigation session. 'clear' resets it mid-session.
conversation_history = []

# --- 2. Logging & Case Management ---

class CaseManager:
    """Manages a Markdown-based forensic log for the investigation session."""
    def __init__(self):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.filename = f"case_log_{timestamp}.md"
        with open(self.filename, "w") as f:
            f.write(f"# Forensic Investigation Log: {timestamp}\n")
            f.write(f"**Started:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Analyst Station:** {os.uname().nodename}\n\n---\n")
        print(f"[*] Case Log initialized: {self.filename}")

    def log_event(self, section_title, content):
        with open(self.filename, "a") as f:
            f.write(f"## {section_title}\n")
            f.write(f"{content}\n\n")
            f.write("---\n")

# --- 3. Helper Functions ---

def check_virustotal(ip_address):
    """Enriches the investigation with external threat intelligence."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return "[-] VirusTotal: No API key found. Skipping lookup."

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious = stats['malicious']
            if malicious > 0:
                return f"⚠️ ALERT: VirusTotal flags this IP as MALICIOUS ({malicious} hits)."
            return "✅ VirusTotal: IP appears clean."
        return f"[-] VirusTotal: Lookup failed (HTTP {response.status_code})."
    except Exception as e:
        return f"[-] VirusTotal Error: {str(e)}"

def parse_siem_alert(raw_input):
    """Parses the SIEM alert format and returns structured data and a prompt."""
    try:
        parts = [p.strip() for p in raw_input.split(',')]
        data = {}
        for part in parts:
            if ':' in part:
                # limit=1 so values that contain colons (e.g. future IPv6) are preserved intact
                key, val = part.split(':', 1)
                data[key.strip()] = val.strip()

        analysis_prompt = (
            f"SIEM ALERT ANALYSIS REQUEST:\n"
            f"- Source (Internet): {data.get('sm_src_ip')}\n"
            f"- Destination (DMZ Web): {data.get('sm_dst_ip')}:{data.get('sm_dst_port')}\n"
            f"- Application/Action: {data.get('sm_app')} / {data.get('sm_action')}\n"
            f"- Target Internal Oracle DB: {data.get('sm_oracle_db_ip')}\n\n"
            f"Evaluate the threat of Initial Access on the Web Server ({data.get('sm_dst_ip')}) "
            f"and possible Lateral Movement to the Oracle host ({data.get('sm_oracle_db_ip')})."
        )
        return data, analysis_prompt
    except Exception:
        return None, None

def run_remote_command(target_ip, command):
    """Executes a forensic command on a remote Linux host via SSH."""
    allowed_prefixes = ("grep", "journalctl", "ps", "who", "ls", "cat", "tail", "netstat", "ss", "sqlplus", "aureport", "ausearch")

    # Strip a leading 'sudo' before checking the prefix so analysts can run
    # privileged variants (e.g. 'sudo netstat') without bypassing the allow-list.
    stripped = command.strip()
    if stripped.startswith("sudo "):
        stripped = stripped[5:].strip()
    if not any(stripped.startswith(p) for p in allowed_prefixes):
        return "BLOCKED: Command not in the forensic safety allow-list."

    ssh_cmd = ["ssh", "-o", "ConnectTimeout=5", target_ip, command]

    confirm = input(f"\n[?] SYSTEM PERMISSION: Run command on {target_ip}?\nCommand: {command}\nProceed? (y/n): ")
    if confirm.lower() == 'y':
        try:
            result = subprocess.run(ssh_cmd, capture_output=True, text=True)
            output = result.stdout.strip()
            if result.returncode == 0:
                return output if output else "Command executed successfully (no matches/output)."
            elif result.returncode == 1 and not output:
                # grep exits 1 when it finds no matches — that is a valid result,
                # not an execution error.
                return "No matches found."
            else:
                return f"Remote Execution Error ({target_ip}) [exit {result.returncode}]:\n{result.stderr}"
        except Exception as e:
            return f"Remote Execution Error ({target_ip}):\n{str(e)}"
    return "Execution skipped by user."

def ask_bedrock(prompt_text, is_system_result=False):
    """Interfaces with AWS Bedrock (Claude Haiku 4.5)."""
    # Tag command output distinctly so the model treats it as observational
    # evidence rather than analyst instructions.
    formatted_input = f"--- OBSERVED SYSTEM OUTPUT ---\n{prompt_text}" if is_system_result else prompt_text

    conversation_history.append({
        "role": "user",
        "content": [{"type": "text", "text": formatted_input}]
    })

    native_request = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 2000,
        # Low temperature keeps forensic recommendations consistent and reproducible.
        "temperature": 0.2,
        "system": SYSTEM_PROMPT,
        "messages": conversation_history
    }

    try:
        response = client.invoke_model(modelId=model_id, body=json.dumps(native_request))
        response_body = json.loads(response["body"].read())
        assistant_text = response_body["content"][0]["text"]

        conversation_history.append({
            "role": "assistant",
            "content": [{"type": "text", "text": assistant_text}]
        })
        return assistant_text
    except Exception as e:
        return f"CRITICAL BEDROCK ERROR: {str(e)}"

# --- 4. Main Interactive Loop ---

def main():
    case = CaseManager()
    print("==================================================")
    print("         AI INCIDENT RESPONSE AGENT               ")
    print("      Forensic Orchestrator: DMZ & Internal       ")
    print("==================================================")
    print("Commands: 'help' for usage | 'exit' to quit | 'clear' to reset memory")

    while True:
        user_input = input("\n[Input] > ").strip()
        if not user_input: continue
        if user_input.lower() == 'exit': break
        if user_input.lower() == 'help':
            print("""
SIEM ALERT FORMAT (comma-separated key:value pairs):
  sm_log_type     - Log source (e.g., Palo Alto Firewall)
  sm_src_ip       - Source IP address (Internet-facing attacker)
  sm_dst_ip       - Destination IP address (DMZ Web Server)
  sm_src_port     - Source port number
  sm_dst_port     - Destination port number
  sm_app          - Application identified by the firewall (e.g., web-browsing, ssl)
  sm_action       - Firewall action taken (e.g., allow, deny, drop)
  sm_oracle_db_ip - Internal Oracle Database IP for lateral movement analysis

EXAMPLE:
  sm_log_type:Palo Alto Firewall, sm_src_ip:45.182.189.102, sm_dst_ip:10.0.0.4, sm_src_port:13424, sm_dst_port:443, sm_app:web-browsing, sm_action:allow, sm_oracle_db_ip:172.18.18.2

FREE-FORM QUESTIONS:
  You can also type any natural-language question or observation and the AI will analyse it in context.
  Example: "The web server process is running as root, is this a concern?"
""")
            continue
        if user_input.lower() == 'clear':
            conversation_history.clear()
            print("[*] Memory cleared.")
            continue

        current_alert_data = {}
        processed_prompt = user_input

        # 1. Parsing & Enrichment
        if "sm_log_type" in user_input:
            alert_data, prompt = parse_siem_alert(user_input)
            if alert_data:
                current_alert_data = alert_data
                src_ip = alert_data.get('sm_src_ip')
                print(f"[*] Consulting VirusTotal for Source IP: {src_ip}...")
                vt_report = check_virustotal(src_ip)
                processed_prompt = f"{prompt}\n\nExternal Intel: {vt_report}"
                case.log_event("SIEM Alert Received", f"**Input:** `{user_input}`\n\n**VT Report:** {vt_report}")

        # 2. Initial AI Analysis
        print("[*] Consulting Bedrock...")
        analysis = ask_bedrock(processed_prompt)
        print(f"\n[AI ANALYSIS]\n{analysis}")
        case.log_event("AI Initial Analysis", analysis)

        # 3. Persistent Forensic Loop
        while True:
            # Use parsed IPs for the prompt hint
            web_ip = current_alert_data.get('sm_dst_ip', '10.0.0.4')
            db_ip = current_alert_data.get('sm_oracle_db_ip', '172.18.18.2')

            print("\n" + "-"*40)
            print("AI Suggested Forensics. Run command or Enter to finish.")
            target_host = input(f"Target IP (e.g., {web_ip} or {db_ip}) [Enter to skip]: ").strip()

            if not target_host:
                break # Exit forensic loop, back to main input

            cmd_input = input(f"Command for {target_host}: ").strip()

            if cmd_input:
                output = run_remote_command(target_host, cmd_input)
                print(f"\n[COMMAND OUTPUT]:\n{output}")

                # Feedback loop: AI evaluates the output
                print("[*] Sending output back to AI for final validation...")
                final_verdict = ask_bedrock(f"Target: {target_host}\nOutput: {output}", is_system_result=True)

                print(f"\n[AI NEXT STEP / VERDICT]\n{final_verdict}")

                # Log the command and the evaluation
                case.log_event(f"Forensic Action: {target_host}",
                    f"**Command:** `{cmd_input}`\n\n**Output:**\n\n**AI Verdict:**\n{final_verdict}")
            else:
                break

if __name__ == "__main__":
    main()
