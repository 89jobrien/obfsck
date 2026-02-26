use std::collections::HashMap;

pub const SYSTEM_PROMPT: &str = r#"You are a senior security analyst and incident responder with deep expertise in:
- Container security and Kubernetes
- Linux system internals and syscalls
- MITRE ATT&CK framework
- Threat hunting and forensics
- Defensive security and hardening

You are analyzing security alerts from Falco, a runtime security tool that monitors system calls and container activity. Your role is to help security teams understand and respond to potential threats.

IMPORTANT CONTEXT:
- All personally identifiable information has been obfuscated (IPs, hostnames, usernames, etc.)
- Tokens like [USER-1], [HOST-1], [IP-EXTERNAL-1], [IP-INTERNAL-1] represent redacted values
- Focus on BEHAVIOR and PATTERNS, not specific redacted values
- Alerts are from production systems and should be treated seriously

For each alert, provide:
1) ATTACK VECTOR: What the attacker is likely trying to accomplish.
2) MITRE ATT&CK MAPPING: Tactic + technique ID/name + sub-technique when applicable.
3) RISK ASSESSMENT: Severity (Critical/High/Medium/Low), confidence (High/Medium/Low), and impact.
4) INDICATORS TO INVESTIGATE: Related activity, logs, artifacts, and validation checks.
5) MITIGATION STRATEGIES: Immediate containment, short-term prevention, long-term hardening.
6) FALSE POSITIVE ASSESSMENT: Common benign causes and distinguishing factors.

Respond in strict JSON with these exact keys and shape:
{
  "attack_vector": "string",
  "mitre_attack": {
    "tactic": "string",
    "technique_id": "string",
    "technique_name": "string",
    "sub_technique": "string or null"
  },
  "risk": {
    "severity": "Critical|High|Medium|Low",
    "confidence": "High|Medium|Low",
    "impact": "string"
  },
  "investigate": ["string"],
  "mitigations": {
    "immediate": ["string"],
    "short_term": ["string"],
    "long_term": ["string"]
  },
  "false_positive": {
    "likelihood": "High|Medium|Low",
    "common_causes": ["string"],
    "distinguishing_factors": ["string"]
  },
  "summary": "string"
}

Do not include markdown, commentary, or prose outside JSON. Be concise but actionable."#;

pub const USER_PROMPT_TEMPLATE: &str = r#"Analyze this security alert.

Rule: {rule_name}
Priority: {priority}
Timestamp: {timestamp}
Source: {source}

Alert details:
{obfuscated_output}

Additional context:
- container_image: {container_image}
- syscall: {syscall}
- process: {process}
- parent_process: {parent_process}

Return only strict JSON matching the required schema."#;

pub fn mitre_mapping() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        (
            "Read sensitive file untrusted",
            "Credential Access / T1003.008 OS Credential Dumping: /etc/passwd and /etc/shadow",
        ),
        (
            "Write below etc",
            "Persistence / T1543 Create or Modify System Process",
        ),
        (
            "Terminal shell in container",
            "Execution / T1059.004 Command and Scripting Interpreter: Unix Shell",
        ),
        (
            "Write below binary dir",
            "Persistence / T1543 Create or Modify System Process",
        ),
        (
            "Container Running as Root",
            "Privilege Escalation / T1611 Escape to Host",
        ),
        (
            "Outbound Connection to Suspicious Port",
            "Command and Control / T1571 Non-Standard Port",
        ),
        (
            "Outbound connection",
            "Command and Control / T1071 Application Layer Protocol",
        ),
        (
            "Reverse Shell Spawned",
            "Execution / T1059.004 Command and Scripting Interpreter: Unix Shell",
        ),
        (
            "Crypto Mining Activity",
            "Impact / T1496 Resource Hijacking",
        ),
        (
            "Package management process launched",
            "Execution / T1072 Software Deployment Tools",
        ),
        (
            "Clear log activities",
            "Defense Evasion / T1070.002 Indicator Removal: Clear Linux or Mac System Logs",
        ),
        (
            "Data Exfiltration via Curl",
            "Exfiltration / T1048 Exfiltration Over Alternative Protocol",
        ),
    ])
}
