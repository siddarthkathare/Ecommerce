import json
import os
import re
import sys
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ml_model import risk_model  # noqa: E402


GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/interactions"
MODEL = "gemini-3.5-flash-lite"


def redact_secrets(value):
    """
    Redact obvious API keys/secrets before sending project data to Gemini.
    """
    if isinstance(value, dict):
        return {k: redact_secrets(v) for k, v in value.items()}

    if isinstance(value, list):
        return [redact_secrets(v) for v in value]

    if isinstance(value, str):
        patterns = [
            r"gsk_[A-Za-z0-9_-]+",
            r"AIza[A-Za-z0-9_-]+",
            r"sk-[A-Za-z0-9_-]+",
        ]

        for pattern in patterns:
            value = re.sub(pattern, "[REDACTED_SECRET]", value)

        return value

    return value


def load_source_code():
    """
    Load relevant project files so Gemini can suggest corrected code.
    """
    files = [
        os.path.join("vulnerable_target", "vulnerable_app.py"),
        os.path.join("vulnerable_target", "Dockerfile"),
        "requirements.txt"
    ]

    source = {}

    for filename in files:
        if os.path.exists(filename):
            try:
                with open(filename, "r", encoding="utf-8") as file:
                    content = file.read()

                source[filename] = redact_secrets(content)

            except Exception as error:
                source[filename] = f"Unable to read file: {error}"

    return source


def parse_ver(v_str):
    if not v_str:
        return (0, 0, 0)
    nums = re.findall(r'\d+', str(v_str))
    return tuple(int(n) for n in nums) if nums else (0, 0, 0)


def pick_highest_fixed_version(fixed_versions):
    valid = [v for v in fixed_versions if v and str(v).lower() not in ("fixed", "latest", "n/a", "none")]
    if not valid:
        return "latest"
    return max(valid, key=parse_ver)


SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def generate_fallback_findings(trivy_report, source_code):
    findings = []
    
    if isinstance(trivy_report, dict):
        grouped_vulns = {}

        for result in trivy_report.get("Results", []):
            target = result.get("Target", "project")
            
            for vuln in (result.get("Vulnerabilities", []) or []):
                pkg_name = vuln.get("PkgName", "package")
                key = (target, pkg_name)
                if key not in grouped_vulns:
                    grouped_vulns[key] = {
                        "target": target,
                        "pkg_name": pkg_name,
                        "installed_version": vuln.get("InstalledVersion", "unknown"),
                        "cves": [],
                        "severities": [],
                        "fixed_versions": [],
                        "descriptions": []
                    }
                
                cve_id = vuln.get("VulnerabilityID", "CVE-UNKNOWN")
                if cve_id not in grouped_vulns[key]["cves"]:
                    grouped_vulns[key]["cves"].append(cve_id)
                
                sev = vuln.get("Severity", "HIGH").upper()
                grouped_vulns[key]["severities"].append(sev)
                
                fix_v = vuln.get("FixedVersion")
                if fix_v:
                    grouped_vulns[key]["fixed_versions"].append(fix_v)
                
                desc = vuln.get("Title") or vuln.get("Description") or ""
                if desc and desc not in grouped_vulns[key]["descriptions"]:
                    grouped_vulns[key]["descriptions"].append(desc)

            for secret in (result.get("Secrets", []) or []):
                sev = secret.get("Severity", "CRITICAL").upper()
                line = secret.get("StartLine", None)
                title = secret.get("Title", "Exposed Secret/Credential")
                
                findings.append({
                    "vulnerability": f"Hardcoded Secret: {title}",
                    "cve": "N/A",
                    "package_file": f"{target}" + (f" (line {line})" if line else ""),
                    "file": target,
                    "line": line,
                    "current_version": "[REDACTED SECRET]",
                    "severity": sev,
                    "why_it_matters": f"A hardcoded credential ({title}) was detected in source code.",
                    "secure_version": "Use environment variables or a key vault",
                    "recommended_fix": f"Remove credential from {target}, revoke key, and load via environment variables.",
                    "issue": f"Hardcoded Secret: {title}",
                    "explanation": f"A hardcoded credential ({title}) was detected in source code.",
                    "vulnerable_code": "[REDACTED SECRET]",
                    "secure_code": "SECRET_KEY = os.environ.get('SECRET_KEY')",
                    "why_fix_works": "Prevents secret leakage in version control.",
                    "developer_action": f"Remove credential from {target}, revoke key, and load via environment variables."
                })

        for (target, pkg_name), data in grouped_vulns.items():
            highest_sev = max(data["severities"], key=lambda s: SEVERITY_RANK.get(s, 0))
            highest_fixed = pick_highest_fixed_version(data["fixed_versions"])
            cve_str = ", ".join(data["cves"])
            desc_str = " ".join(data["descriptions"][:2])
            
            findings.append({
                "vulnerability": f"Vulnerable Dependency: {pkg_name}",
                "cve": cve_str,
                "package_file": f"{target} ({pkg_name})",
                "file": target,
                "line": None,
                "current_version": data["installed_version"],
                "severity": highest_sev,
                "why_it_matters": f"{pkg_name} {data['installed_version']} contains {len(data['cves'])} vulnerabilities ({cve_str}). {desc_str}".strip(),
                "secure_version": f"{pkg_name} >= {highest_fixed}",
                "recommended_fix": f"Update {pkg_name} in {target} to version {highest_fixed} or higher.",
                "issue": f"Vulnerable Dependency: {pkg_name} ({cve_str})",
                "explanation": f"{pkg_name} {data['installed_version']} contains {len(data['cves'])} vulnerabilities ({cve_str}). {desc_str}".strip(),
                "vulnerable_code": f"{pkg_name}=={data['installed_version']}",
                "secure_code": f"{pkg_name}>={highest_fixed}",
                "why_fix_works": f"Upgrading {pkg_name} to version {highest_fixed} addresses all detected CVEs ({cve_str}).",
                "developer_action": f"Update {pkg_name} in {target} to version {highest_fixed} or higher."
            })

        return {"findings": findings}

    return {"findings": findings}


def analyze_with_gemini(findings, source_code):
    api_key = os.environ.get("GEMINI_API_KEY")

    trivy_raw = findings.get("trivy", {})
    if not api_key:
        print("WARNING: GEMINI_API_KEY is not available. Using local analysis generator.")
        return json.dumps(generate_fallback_findings(trivy_raw, source_code))

    safe_findings = redact_secrets(findings)
    safe_source = redact_secrets(source_code)

    prompt = f"""
You are an expert DevSecOps security assistant.

Analyze the security findings from a CI/CD security pipeline.

SECURITY FINDINGS:
{json.dumps(safe_findings, indent=2)}

PROJECT SOURCE CODE:
{json.dumps(safe_source, indent=2)}

RULES:
1. Base findings ONLY on actual Trivy scanner findings and source code. Do NOT invent CVEs, vulnerabilities, or line numbers.
2. Group duplicate CVEs or vulnerabilities affecting the same dependency package into a SINGLE finding entry.
3. Provide ONE consolidated secure version recommendation for each affected dependency.
4. Return ONLY valid JSON with this exact structure:

{{
  "findings": [
    {{
      "vulnerability": "Vulnerable Dependency: requests",
      "cve": "CVE-2018-18074, CVE-2023-32681, CVE-2024-35195, CVE-2024-47081, CVE-2026-25645",
      "package_file": "requirements.txt (requests)",
      "file": "requirements.txt",
      "current_version": "2.19.1",
      "severity": "HIGH",
      "why_it_matters": "Explanation of vulnerability risk",
      "secure_version": "requests >= 2.33.0",
      "recommended_fix": "Update requirements.txt to requests>=2.33.0",
      "issue": "Vulnerable Dependency: requests",
      "explanation": "Explanation of vulnerability risk",
      "vulnerable_code": "requests==2.19.1",
      "secure_code": "requests>=2.33.0",
      "why_fix_works": "Upgrading patches all detected CVEs",
      "developer_action": "Update requirements.txt to requests>=2.33.0"
    }}
  ]
}}
"""

    payload = {
        "model": MODEL,
        "input": prompt
    }

    request = urllib.request.Request(
        GEMINI_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "x-goog-api-key": api_key,
            "Content-Type": "application/json"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            result = json.loads(response.read().decode("utf-8"))

    except Exception as error:
        print(f"Gemini API request failed: {error}. Falling back to local analyzer.")
        return json.dumps(generate_fallback_findings(trivy_raw, source_code))

    for step in result.get("steps", []):
        if step.get("type") == "model_output":

            for content in step.get("content", []):
                if content.get("type") == "text":
                    return content.get("text", "")

    return json.dumps(generate_fallback_findings(trivy_raw, source_code))


def parse_gemini_json(text):
    text = text.strip()

    if text.startswith("```"):
        lines = text.splitlines()

        if lines and lines[0].startswith("```"):
            lines = lines[1:]

        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]

        text = "\n".join(lines).strip()

    try:
        return json.loads(text)

    except json.JSONDecodeError:
        print("WARNING: Gemini did not return valid JSON. Falling back to local structured findings.")
        return {
            "findings": [],
            "raw_report": text
        }


if __name__ == "__main__":

    try:
        with open("trivy-report.json", "r", encoding="utf-8") as file:
            trivy_findings = json.load(file)

    except FileNotFoundError:
        print("ERROR: trivy-report.json not found.")
        sys.exit(1)

    source_code = load_source_code()

    findings = {
        "trivy": trivy_findings
    }

    raw_report = analyze_with_gemini(
        findings,
        source_code
    )

    report = parse_gemini_json(raw_report)

    # Dataset-driven ML risk model: attach a priority prediction to every
    # finding alongside Gemini's generative-AI explanation.
    if risk_model.is_model_available():
        for finding in report.get("findings", []):
            try:
                severity = (finding.get("severity") or "LOW").upper()
                is_secret = "secret" in (finding.get("vulnerability", "") or "").lower()
                cve_field = finding.get("cve", "") or ""
                cve_count = len([c for c in cve_field.split(",") if c.strip()]) or 1
                has_fix = bool(finding.get("secure_version") or finding.get("secure_code"))
                ecosystem = risk_model.guess_ecosystem(
                    finding.get("file") or finding.get("package_file")
                )
                label, confidence = risk_model.predict_priority(
                    severity=severity,
                    is_secret=is_secret,
                    has_fix_available=has_fix,
                    cve_count=cve_count,
                    ecosystem=ecosystem,
                )
                finding["ml_priority"] = label
                finding["ml_confidence"] = confidence
            except Exception:
                continue
    else:
        print("NOTE: no trained ML model found — run ml_model/train_model.py to enable ML risk scoring.")

    # Summarize severity counts according to policy
    critical = 0
    high = 0
    medium = 0
    low = 0

    for res in trivy_findings.get("Results", []):
        for v in res.get("Vulnerabilities", []) or []:
            s = v.get("Severity", "").upper()
            if s == "CRITICAL": critical += 1
            elif s == "HIGH": high += 1
            elif s == "MEDIUM": medium += 1
            elif s == "LOW": low += 1
        for sec in res.get("Secrets", []) or []:
            s = sec.get("Severity", "").upper()
            if s == "CRITICAL": critical += 1
            elif s == "HIGH": high += 1
            elif s == "MEDIUM": medium += 1
            elif s == "LOW": low += 1

    blocked = (critical > 0 or high > 0)
    gate_status = "FAILED" if blocked else "PASSED"
    deployment = "BLOCKED" if blocked else "ALLOWED"

    report["gate_status"] = gate_status
    report["deployment"] = deployment
    report["summary"] = {
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "blocked": blocked
    }

    with open(
        "ai-security-report.json",
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            report,
            file,
            indent=2,
            ensure_ascii=False
        )

    print("\n========== AI SECURITY REPORT ==========\n")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    print("\n========================================\n")
    print(f"CRITICAL findings: {critical}")
    print(f"HIGH findings:     {high}")
    print(f"MEDIUM findings:   {medium}")
    print(f"LOW findings:      {low}")
    print(f"Security Gate:     {gate_status}")
    print(f"Deployment:        {deployment}")
    print("========================================\n")