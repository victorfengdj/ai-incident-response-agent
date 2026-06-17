# AI Incident Response Agent

An AI-powered SOC forensic orchestrator for investigating potential intrusions originating from the Internet, hitting a DMZ Web Server, and potentially moving laterally to an internal Oracle Database.

The agent combines AWS Bedrock (Claude Haiku 4.5), VirusTotal threat intelligence, and SSH-based remote command execution into a single interactive loop. Every session is automatically saved as a Markdown case log.

---

## Architecture

```
Analyst
  │
  ├─ SIEM Alert (Palo Alto firewall log)
  │       │
  │       ├─ VirusTotal IP Reputation Lookup
  │       └─ AWS Bedrock (Claude Haiku 4.5)
  │               │
  │               └─ MITRE ATT&CK Analysis
  │                  Forensic Commands
  │                  Oracle Audit Queries
  │                  Business Case
  │
  ├─ SSH Remote Command Execution
  │       │ (allow-listed commands only)
  │       └─ DMZ Web Server / Oracle DB Host
  │
  └─ Markdown Case Log (case_log_<timestamp>.md)
```

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.8+ | |
| AWS account | Bedrock enabled in `us-east-1` |
| AWS credentials | `aws configure` or IAM role |
| Bedrock model access | Request access to `Claude Haiku 4.5` in the AWS console |
| VirusTotal API key | Free tier is sufficient |
| SSH access | Passwordless SSH to target hosts recommended |

### Python dependencies

```bash
pip3 install boto3 requests python-dotenv
```

---

## Setup

1. Clone the repository:
   ```bash
   git clone <repo-url>
   cd ai-incident-response-agent
   ```

2. Create a `.env` file with your VirusTotal API key:
   ```
   VIRUSTOTAL_API_KEY=your_api_key_here
   ```

3. Confirm AWS credentials are configured:
   ```bash
   aws sts get-caller-identity
   ```

---

## Usage

```bash
python3 ai-incident-response-agent.py
```

Type `help` at the prompt to see the full input reference:

```
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
```

### Session commands

| Command | Action |
|---|---|
| `help` | Show input format and field reference |
| `clear` | Reset AI conversation memory (start fresh context) |
| `exit` | End the session |

### Investigation flow

1. Paste a SIEM alert — the agent automatically queries VirusTotal and sends the enriched alert to Bedrock.
2. The AI returns a MITRE ATT&CK-mapped analysis, suggested forensic commands, Oracle audit SQL, and a business case.
3. At the forensic prompt, enter a target IP and command to run it on the remote host over SSH. The output is fed back to the AI for interpretation.
4. Repeat for each command or press Enter to return to the main prompt.

---

## Remote Command Allow-list

For safety, only the following command prefixes are permitted on remote hosts (with or without a leading `sudo`):

`grep` `journalctl` `ps` `who` `ls` `cat` `tail` `netstat` `ss` `sqlplus` `aureport` `ausearch`

---

## Case Logs

Each session writes a Markdown case log to `case_log_<YYYYMMDD_HHMMSS>.md` in the working directory. Move completed logs to `case_logs/` for archiving.

Sample investigations are provided in [`case_logs/`](case_logs/):

| Log | Source IP | VT Result | Summary |
|---|---|---|---|
| [case_log_20260616_230901.md](case_logs/case_log_20260616_230901.md) | 45.182.189.102 | ⚠️ MALICIOUS (4 hits) | High-severity alert — VirusTotal-flagged IP hitting DMZ web server on HTTPS; MITRE T1190 Initial Access confirmed; forensic investigation initiated |
| [case_log_20260616_231954.md](case_logs/case_log_20260616_231954.md) | 156.146.98.8 | ✅ Clean | Medium-severity alert — clean IP reputation but HTTPS payload opaque; lateral movement to Oracle DB not ruled out; escalated to deep-dive forensics |

---

## AWS Bedrock Model

| Field | Value |
|---|---|
| Provider | Anthropic |
| Model | Claude Haiku 4.5 |
| Inference profile | `us.anthropic.claude-haiku-4-5-20251001-v1:0` |
| Region | `us-east-1` |

The cross-region inference profile (`us.` prefix) is required for on-demand invocation. Direct model IDs are not supported without provisioned throughput.
