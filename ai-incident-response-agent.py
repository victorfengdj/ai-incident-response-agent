#!/usr/bin/python3
import datetime
import subprocess
import os
import boto3
import requests
from anthropic import AnthropicBedrock
from dotenv import load_dotenv

# Load VIRUSTOTAL_API_KEY and any other secrets from a local .env file so the
# script works without manually exporting variables in the shell.
load_dotenv()

# --- 1. Configuration & Persona ---
# Ensure AWS credentials are set via 'aws configure' or IAM Roles.
# Opus 4.6 is served via Bedrock's InvokeModel path — the cross-region
# inference profile ("us." prefix) is required for on-demand invocation.
client = AnthropicBedrock(aws_region="us-east-1")
model_id = "us.anthropic.claude-opus-4-6-v1"

# Optional Bedrock Guardrail (set BEDROCK_GUARDRAIL_ID in .env to enable).
# Configured with the prompt-attack filter: command output fed back from a
# potentially compromised host is attacker-controllable text, so it is
# screened for prompt-injection via the vendor-independent ApplyGuardrail API
# before it reaches the model.
guardrail_id = os.getenv("BEDROCK_GUARDRAIL_ID")
guardrail_version = os.getenv("BEDROCK_GUARDRAIL_VERSION", "DRAFT")
bedrock_runtime = boto3.client("bedrock-runtime", region_name="us-east-1")

def guardrail_screen(text):
    """Screen text with the Bedrock Guardrail. Returns None if the content is
    allowed, or the guardrail's block message if it intervened. No-op (returns
    None) when no guardrail is configured."""
    if not guardrail_id:
        return None
    try:
        result = bedrock_runtime.apply_guardrail(
            guardrailIdentifier=guardrail_id,
            guardrailVersion=guardrail_version,
            source="INPUT",
            content=[{"text": {"text": text}}],
        )
        if result.get("action") == "GUARDRAIL_INTERVENED":
            outputs = result.get("outputs", [])
            msg = outputs[0]["text"] if outputs else "content blocked by guardrail"
            return f"GUARDRAIL BLOCKED: {msg}"
    except Exception as e:
        # Fail closed on unexpected guardrail errors — screening untrusted
        # host output is the whole point, so don't silently pass it through.
        return f"GUARDRAIL ERROR (input not screened): {str(e)}"
    return None

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

Host identifiers such as HOST-A (DMZ web server) and DB-1 (internal Oracle
database) are pseudonymized labels for internal addresses. Use them verbatim
in your analysis, forensic commands, and SQL queries — do not invent IP
addresses for them.

Keep your tone professional, technical, and concise.
"""

# --- Pseudonymization of internal IPs ---
# Internal topology (private IPs + host roles) is Internal/Confidential data.
# The model only ever sees stable tokens; real addresses are re-substituted
# locally before anything is displayed or written to the case log.
ip_token_map = {
    "10.0.0.4": "HOST-A",   # DMZ web server (default lab address)
    "172.18.18.2": "DB-1",  # internal Oracle DB (default lab address)
}

def register_internal_hosts(web_ip, db_ip):
    """(Re)build the IP-to-token map from the current SIEM alert."""
    ip_token_map.clear()
    if web_ip:
        ip_token_map[web_ip] = "HOST-A"
    if db_ip:
        ip_token_map[db_ip] = "DB-1"

def pseudonymize(text):
    """Replace internal IPs with tokens before text is sent to the model."""
    for ip, token in ip_token_map.items():
        text = text.replace(ip, token)
    return text

def reveal(text):
    """Re-substitute real internal IPs for tokens in model output."""
    for ip, token in ip_token_map.items():
        text = text.replace(token, ip)
    return text

# Full conversation history is passed on every call so the model retains context
# across the entire investigation session. 'clear' resets it mid-session.
conversation_history = []

# --- 2. Logging & Case Management ---

class CaseManager:
    """Manages a Markdown-based forensic log for the investigation session."""
    def __init__(self):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        # Store logs in the case_logs/ folder next to this script, regardless
        # of the directory the agent is launched from.
        log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "case_logs")
        os.makedirs(log_dir, exist_ok=True)
        self.filename = os.path.join(log_dir, f"case_log_{timestamp}.md")
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
                return f"ALERT: VirusTotal flags this IP as MALICIOUS ({malicious} hits)."
            return "VirusTotal: IP appears clean."
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
    """Interfaces with AWS Bedrock (Claude Opus 4.6)."""
    # Tag command output distinctly so the model treats it as observational
    # evidence rather than analyst instructions.
    formatted_input = f"--- OBSERVED SYSTEM OUTPUT ---\n{prompt_text}" if is_system_result else prompt_text

    # Internal IPs never leave the machine — the model (and the conversation
    # history sent with every request) only sees HOST-A / DB-1 tokens.
    formatted_input = pseudonymize(formatted_input)

    # Screen the (pseudonymized) input for prompt injection before it reaches
    # the model. Command output fed back from a potentially compromised host is
    # attacker-controllable, so a block here stops a hijacked analysis loop.
    # Screening the pseudonymized text keeps internal IPs off the wire.
    block = guardrail_screen(formatted_input)
    if block:
        return block

    conversation_history.append({
        "role": "user",
        "content": [{"type": "text", "text": formatted_input}]
    })

    # Adaptive thinking is the recommended mode on Opus 4.6 and improves
    # multi-step forensic reasoning; it must be enabled explicitly (the model
    # runs without thinking when the parameter is omitted).
    request_params = {
        "max_tokens": 16000,
        "thinking": {"type": "adaptive"},
        "system": SYSTEM_PROMPT,
        "messages": conversation_history,
    }

    try:
        response = client.messages.create(model=model_id, **request_params)

        # Safety refusals return HTTP 200 with stop_reason "refusal" —
        # surface them to the analyst instead of showing empty output.
        if response.stop_reason == "refusal":
            conversation_history.pop()
            return "REQUEST DECLINED: the model refused this analysis request."

        assistant_text = "".join(
            block.text for block in response.content if block.type == "text"
        )

        # Append the full content (including thinking blocks) so multi-turn
        # context is preserved as the API expects. History keeps the tokens —
        # only the locally displayed/logged text is re-substituted.
        conversation_history.append({
            "role": "assistant",
            "content": response.content
        })
        return reveal(assistant_text)
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
                # Map this alert's internal hosts to pseudonymization tokens
                register_internal_hosts(alert_data.get('sm_dst_ip'),
                                        alert_data.get('sm_oracle_db_ip'))
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
