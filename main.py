#!/usr/bin/env python3
"""
CIS Benchmark Compliance Checker
Author: Andy Sardinas
Description:
    Checks basic CIS compliance rules on a Linux system.
    This script reports status for password policy, SSH configuration,
    and important file permissions.
"""

import os
import re
import subprocess

# Utility function
def run_command(command: str) -> str:
    """Run a shell command safely and return its output."""
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        return result.stdout.strip()
    except Exception as e:
        return f"Error executing {command}: {e}"

def check_password_policy():
    """CIS Rule: Ensure password aging and complexity are enforced."""
    print("\n[1] Checking password policy (CIS 5.4.1.x)...")

    policy = run_command("grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE' /etc/login.defs")
    print(policy if policy else "No password policy found in /etc/login.defs")

    if "PASS_MAX_DAYS" in policy and int(re.search(r'PASS_MAX_DAYS\s+(\d+)', policy).group(1)) <= 365:
        print("✅ PASS_MAX_DAYS within CIS recommended range")
    else:
        print("❌ PASS_MAX_DAYS not set or too long")

def check_ssh_config():
    """CIS Rule: Ensure SSH settings are secure."""
    print("\n[2] Checking SSH configuration (CIS 5.2.x)...")

    sshd_config = "/etc/ssh/sshd_config"
    if not os.path.exists(sshd_config):
        print("❌ SSH config not found")
        return

    content = run_command(f"cat {sshd_config}")
    checks = {
        "PermitRootLogin": "no",
        "Protocol": "2",
        "X11Forwarding": "no",
        "MaxAuthTries": "4",
    }

    for key, expected in checks.items():
        match = re.search(rf'^{key}\s+(\S+)', content, re.MULTILINE)
        if match and match.group(1).lower() == expected:
            print(f"✅ {key} = {expected}")
        else:
            print(f"❌ {key} not set correctly (expected {expected})")

def check_file_permissions():
    """CIS Rule: Ensure important files have secure permissions."""
    print("\n[3] Checking critical file permissions (CIS 6.1.x)...")

    files = {
        "/etc/passwd": "644",
        "/etc/shadow": "640",
        "/etc/group": "644",
    }

    for file, expected_perm in files.items():
        if not os.path.exists(file):
            print(f"❌ {file} not found")
            continue

        actual_perm = oct(os.stat(file).st_mode & 0o777)[2:]
        if actual_perm == expected_perm:
            print(f"✅ {file} permissions = {expected_perm}")
        else:
            print(f"❌ {file} permissions = {actual_perm} (expected {expected_perm})")

def check_firewall_status():
    """CIS Rule: Ensure firewall is enabled."""
    print("\n[4] Checking firewall status (CIS 3.5.x)...")

    ufw_status = run_command("ufw status 2>/dev/null")
    firewalld_status = run_command("systemctl is-active firewalld 2>/dev/null")

    if "active" in ufw_status.lower() or "active" in firewalld_status.lower():
        print("✅ Firewall is active")
    else:
        print("❌ No active firewall detected")

def main():
    print("=== CIS Compliance Checker ===")
    check_password_policy()
    check_ssh_config()
    check_file_permissions()
    check_firewall_status()
    print("\nCompliance check complete.")

if __name__ == "__main__":
    main()
    input("Press enter to close program")