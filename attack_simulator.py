#!/usr/bin/env python3
"""
Sophisticated Attack Simulator for LoneWarrior Testing

This script simulates various attack vectors to test LoneWarrior's detection
and mitigation capabilities:
1. SSH Brute Force Attacks
2. Network Scanning
3. Connection Flood (DDoS-like)
4. Process Spawning (suspicious executables)
5. File System Modifications
6. Port Sweeping
"""

import os
import sys
import time
import random
import socket
import threading
import subprocess
import signal
from pathlib import Path
from datetime import datetime
import argparse

# Color codes for output
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
RESET = '\033[0m'

class AttackSimulator:
    def __init__(self, target_ip="127.0.0.1", duration=60, intensity="medium"):
        self.target_ip = target_ip
        self.duration = duration
        self.intensity = intensity
        self.running = False
        self.threads = []

        # Intensity settings
        self.intensity_map = {
            "low": {"connections": 10, "auth_attempts": 20, "scan_ports": 50, "spawn_processes": 2},
            "medium": {"connections": 50, "auth_attempts": 100, "scan_ports": 200, "spawn_processes": 5},
            "high": {"connections": 200, "auth_attempts": 500, "scan_ports": 1000, "spawn_processes": 10},
            "extreme": {"connections": 500, "auth_attempts": 2000, "scan_ports": 5000, "spawn_processes": 20}
        }
        self.settings = self.intensity_map.get(intensity, self.intensity_map["medium"])

    def log(self, message, color=GREEN):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{color}[{timestamp}] {message}{RESET}")

    def ssh_brute_force(self):
        """Simulate SSH brute force attack"""
        self.log(f"{MAGENTA}Starting SSH Brute Force Attack ({self.settings['auth_attempts']} attempts)", YELLOW)

        # Create fake SSH auth log entries
        for i in range(self.settings["auth_attempts"]):
            if not self.running:
                break

            username = random.choice(["admin", "root", "test", "user", "deploy", "nagios", "backup"])
            ip = f"192.168.1.{random.randint(100, 250)}"

            # Write to auth.log (if we have permission)
            try:
                # Try multiple auth log locations
                auth_log_paths = ['/var/log/auth.log', '/var/log/syslog', '/var/log/messages']
                for log_path in auth_log_paths:
                    try:
                        # Standard auth.log format that matches auth_collector patterns
                        timestamp = datetime.now().strftime('%b %d %H:%M:%S')
                        hostname = os.uname().nodename
                        auth_log_entry = f"{timestamp} {hostname} sshd[{random.randint(1000, 9999)}]: Invalid user {username} from {ip} port {random.randint(10000, 60000)}"
                        with open(log_path, "a") as f:
                            f.write(auth_log_entry + "\n")
                        break  # Successfully written to one file
                    except (PermissionError, FileNotFoundError):
                        continue
            except Exception as e:
                pass

            # Simulate SSH connection attempt
            try:
                subprocess.run(
                    ["nc", "-z", "-w", "1", self.target_ip, "22"],
                    capture_output=True,
                    timeout=2
                )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            time.sleep(0.1 if self.intensity in ["high", "extreme"] else 0.5)

        self.log(f"{GREEN}SSH Brute Force Attack completed", GREEN)

    def network_scan(self):
        """Simulate network scanning attack"""
        self.log(f"{MAGENTA}Starting Network Port Scan ({self.settings['scan_ports']} ports)", YELLOW)

        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 5900, 8080]
        scan_ports = common_ports + list(range(8000, 8100)) + list(range(9000, 9100))

        for i, port in enumerate(scan_ports[:self.settings["scan_ports"]]):
            if not self.running:
                break

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((self.target_ip, port))
                sock.close()

                if i % 50 == 0:
                    self.log(f"Scanning port {port}/{self.settings['scan_ports']}", BLUE)

            except socket.error:
                pass

            time.sleep(0.01)

        self.log(f"{GREEN}Network Scan completed", GREEN)

    def connection_flood(self):
        """Simulate DDoS-like connection flood"""
        self.log(f"{MAGENTA}Starting Connection Flood ({self.settings['connections']} connections)", YELLOW)

        for i in range(self.settings["connections"]):
            if not self.running:
                break

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((self.target_ip, 80))
                time.sleep(0.01)
                sock.close()

                if i % 20 == 0:
                    self.log(f"Sent {i}/{self.settings['connections']} connections", BLUE)

            except (socket.error, socket.timeout, ConnectionRefusedError):
                pass

            if self.intensity in ["high", "extreme"]:
                time.sleep(0.01)
            else:
                time.sleep(0.05)

        self.log(f"{GREEN}Connection Flood completed", GREEN)

    def process_spawning(self):
        """Simulate suspicious process spawning"""
        self.log(f"{MAGENTA}Starting Suspicious Process Spawning ({self.settings['spawn_processes']} processes)", YELLOW)

        suspicious_commands = [
            ["sleep", "30"],
            ["yes", "> /dev/null"],
            ["cat", "/etc/passwd"],
            ["cat", "/etc/shadow"],
        ]

        for i in range(self.settings["spawn_processes"]):
            if not self.running:
                break

            cmd = random.choice(suspicious_commands)

            try:
                # Start process in background
                proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                # Let it run briefly
                time.sleep(2)

                # Terminate it
                proc.terminate()
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    proc.kill()

                self.log(f"Spawned and terminated suspicious process: {' '.join(cmd)}", BLUE)

            except (PermissionError, FileNotFoundError):
                pass

            time.sleep(1)

        self.log(f"{GREEN}Process Spawning Attack completed", GREEN)

    def file_modification(self):
        """Simulate file integrity violations"""
        self.log(f"{MAGENTA}Starting File Modification Attack", YELLOW)

        test_files = [
            "/tmp/test_malware.sh",
            "/tmp/test_backdoor.php",
            "/tmp/test_webshell.jsp",
        ]

        for test_file in test_files:
            if not self.running:
                break

            try:
                # Create suspicious file
                content = f"#!/bin/bash\n# Malicious file created at {datetime.now()}\necho 'Attacker was here'"

                with open(test_file, "w") as f:
                    f.write(content)

                self.log(f"Created suspicious file: {test_file}", BLUE)

                time.sleep(1)

                # Remove it after a delay
                os.remove(test_file)

            except (PermissionError, OSError) as e:
                self.log(f"Could not create {test_file}: {e}", RED)

        self.log(f"{GREEN}File Modification Attack completed", GREEN)

    def port_sweep(self):
        """Simulate port sweeping to many IPs"""
        self.log(f"{MAGENTA}Starting Port Sweep Attack", YELLOW)

        target_ips = [
            "192.168.1.1",
            "192.168.1.2",
            "192.168.1.10",
            "192.168.1.100",
            "10.0.0.1",
        ]

        for ip in target_ips:
            if not self.running:
                break

            for port in [22, 80, 443, 3306]:
                try:
                    subprocess.run(
                        ["nc", "-z", "-w", "1", ip, str(port)],
                        capture_output=True,
                        timeout=2
                    )
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass

                time.sleep(0.1)

            self.log(f"Swept {ip} for open ports", BLUE)

        self.log(f"{GREEN}Port Sweep Attack completed", GREEN)

    def run_all_attacks(self):
        """Run all attack types"""
        self.running = True

        # Start all attacks in threads
        attacks = [
            ("SSH Brute Force", self.ssh_brute_force),
            ("Network Scan", self.network_scan),
            ("Connection Flood", self.connection_flood),
            ("Process Spawning", self.process_spawning),
            ("File Modification", self.file_modification),
            ("Port Sweep", self.port_sweep),
        ]

        threads = []
        for name, attack_func in attacks:
            thread = threading.Thread(target=attack_func)
            thread.start()
            threads.append(thread)
            time.sleep(2)  # Stagger attacks slightly

        # Wait for all threads
        for thread in threads:
            thread.join()

        self.running = False

    def run_sequential_attacks(self):
        """Run attacks sequentially for better observation"""
        self.running = True

        self.log(f"{'='*60}", MAGENTA)
        self.log(f"Starting Sequential Attack Simulation", MAGENTA)
        self.log(f"Target: {self.target_ip}", MAGENTA)
        self.log(f"Intensity: {self.intensity}", MAGENTA)
        self.log(f"{'='*60}", MAGENTA)
        print()

        attacks = [
            ("SSH Brute Force", self.ssh_brute_force),
            ("Network Scan", self.network_scan),
            ("Connection Flood", self.connection_flood),
            ("Process Spawning", self.process_spawning),
            ("File Modification", self.file_modification),
            ("Port Sweep", self.port_sweep),
        ]

        for i, (name, attack_func) in enumerate(attacks):
            self.log(f"\n{'='*60}", MAGENTA)
            self.log(f"Attack {i+1}/{len(attacks)}: {name}", MAGENTA)
            self.log(f"{'='*60}", MAGENTA)

            attack_func()
            time.sleep(3)  # Pause between attacks

        self.log(f"\n{'='*60}", MAGENTA)
        self.log(f"All attacks completed!", MAGENTA)
        self.log(f"{'='*60}", MAGENTA)

        self.running = False


def main():
    parser = argparse.ArgumentParser(description="Sophisticated Attack Simulator for LoneWarrior Testing")
    parser.add_argument("--target", "-t", default="127.0.0.1", help="Target IP address (default: 127.0.0.1)")
    parser.add_argument("--intensity", "-i", choices=["low", "medium", "high", "extreme"], default="medium", help="Attack intensity")
    parser.add_argument("--mode", "-m", choices=["sequential", "parallel"], default="sequential", help="Attack mode")
    parser.add_argument("--duration", "-d", type=int, default=60, help="Duration in seconds")

    args = parser.parse_args()

    simulator = AttackSimulator(
        target_ip=args.target,
        duration=args.duration,
        intensity=args.intensity
    )

    try:
        if args.mode == "parallel":
            simulator.run_all_attacks()
        else:
            simulator.run_sequential_attacks()

    except KeyboardInterrupt:
        print(f"\n{RED}Attack simulation interrupted by user{RESET}")
        simulator.running = False

    print(f"\n{GREEN}Simulation finished. Check LoneWarrior logs for detection and response.{RESET}")


if __name__ == "__main__":
    main()
