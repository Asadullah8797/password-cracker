#!/usr/bin/env python3
import hashlib
import itertools
import string
import time
import argparse
import os
import sys
import sqlite3
import threading
import subprocess
from queue import Queue
from typing import Optional, Dict, Callable, List
import paramiko  # For distributed cracking

# Check if running on Kali Linux
if not os.path.exists('/etc/os-release') or 'kali' not in open('/etc/os-release').read().lower():
    print("Warning: This tool is optimized for Kali Linux. Some features may not work properly.")

# Check for Hashcat (for GPU acceleration)
HASHCAT_PATH = '/usr/bin/hashcat'
HASHCAT_AVAILABLE = os.path.exists(HASHCAT_PATH)

# Supported hash algorithms
HASH_FUNCTIONS: Dict[str, Callable] = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha256': hashlib.sha256,
    'sha512': hashlib.sha512,
    'sha3_256': hashlib.sha3_256,
    'sha3_512': hashlib.sha3_512,
    'blake2b': hashlib.blake2b,
    'blake2s': hashlib.blake2s,
    'ntlm': lambda x: hashlib.new('md4', x.encode('utf-16le')).hexdigest(),
}

class DistributedCracker:
    def __init__(self, nodes: List[dict]):
        """Initialize distributed cracking with SSH nodes"""
        self.nodes = nodes
        self.connections = []
        self._connect_nodes()

    def _connect_nodes(self):
        """Establish SSH connections to all nodes"""
        for node in self.nodes:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(node['host'], port=node.get('port', 22), 
                          username=node['user'], password=node.get('password'),
                          key_filename=node.get('keyfile'))
                self.connections.append(ssh)
                print(f"[+] Connected to {node['host']}")
            except Exception as e:
                print(f"[-] Failed to connect to {node['host']}: {str(e)}")

    def distribute_work(self, hash_type: str, target_hash: str, wordlist: Optional[str] = None,
                      brute_config: Optional[dict] = None):
        """Distribute cracking work across nodes"""
        if not self.connections:
            print("[-] No active connections to distribute work")
            return None

        # Split work based on attack type
        if wordlist:
            return self._distribute_wordlist(hash_type, target_hash, wordlist)
        elif brute_config:
            return self._distribute_bruteforce(hash_type, target_hash, brute_config)
        else:
            print("[-] No valid attack configuration provided")
            return None

    def _distribute_wordlist(self, hash_type: str, target_hash: str, wordlist_path: str):
        """Distribute dictionary attack across nodes"""
        # Implement wordlist splitting and distribution
        pass  # Actual implementation would handle file transfer and parallel processing

    def _distribute_bruteforce(self, hash_type: str, target_hash: str, config: dict):
        """Distribute brute force attack across nodes"""
        # Implement keyspace division and distribution
        pass  # Actual implementation would divide the keyspace

class KaliPasswordCracker:
    def __init__(self, hash_type: str, threads: int = None, use_gpu: bool = False):
        self.hash_func = HASH_FUNCTIONS.get(hash_type.lower())
        if not self.hash_func:
            raise ValueError(f"Unsupported hash type: {hash_type}")
        
        # Automatically detect optimal thread count if not specified
        self.threads = threads or os.cpu_count() or 4
        self.use_gpu = use_gpu and HASHCAT_AVAILABLE
        self.found = False
        self.result = None
        self.lock = threading.Lock()
        self.queue = Queue()
        self.hash_type = hash_type.lower()
        self.start_time = time.time()

        # Performance metrics
        self.tested = 0
        self.rate = 0

    def _hash(self, password: str) -> str:
        """Generate hash for the given password"""
        return self.hash_func(password.encode()).hexdigest()

    def _update_stats(self, count: int):
        """Update performance statistics"""
        with self.lock:
            self.tested += count
            elapsed = time.time() - self.start_time
            if elapsed > 0:
                self.rate = self.tested / elapsed

    def _print_progress(self):
        """Display progress information"""
        elapsed = time.time() - self.start_time
        print(f"\r[+] Tested: {self.tested:,} | Rate: {self.rate:,.0f} hashes/sec | Elapsed: {elapsed:.1f}s", end='')
        sys.stdout.flush()

    def _try_hashcat(self, target_hash: str, attack_mode: str, attack_config: str) -> Optional[str]:
        """Attempt to use Hashcat for GPU acceleration"""
        if not self.use_gpu:
            return None

        hashcat_mode = {
            'md5': 0,
            'sha1': 100,
            'sha256': 1400,
            'sha512': 1700,
            'ntlm': 1000,
        }.get(self.hash_type)

        if hashcat_mode is None:
            return None

        try:
            # Create temporary hash file
            with open('/tmp/hashcat_target.hash', 'w') as f:
                f.write(target_hash)

            cmd = [
                HASHCAT_PATH,
                '-m', str(hashcat_mode),
                '-a', attack_mode,
                '/tmp/hashcat_target.hash',
                *attack_config.split()
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)
            if 'Cracked' in result.stdout:
                for line in result.stdout.split('\n'):
                    if target_hash in line:
                        return line.split(':')[-1]
        except Exception as e:
            print(f"[-] Hashcat error: {str(e)}")
        return None

    def dictionary_attack(self, target_hash: str, wordlist_path: str) -> Optional[str]:
        """Perform optimized dictionary attack with variations"""
        # First try Hashcat if GPU is enabled
        if self.use_gpu:
            if result := self._try_hashcat(target_hash, '0', wordlist_path):
                return result

        try:
            file_size = os.path.getsize(wordlist_path)
            chunk_size = 1024 * 1024  # 1MB chunks for progress reporting
            processed = 0

            with open(wordlist_path, 'r', encoding='latin-1', errors='ignore') as f:
                for word in f:
                    if self.found:
                        break

                    word = word.strip()
                    processed += len(word.encode()) + 1  # +1 for newline

                    # Basic check
                    if self._hash(word) == target_hash:
                        self.found = True
                        self.result = word
                        break

                    # Common variations
                    variations = [
                        word.capitalize(),
                        word.upper(),
                        word + '123',
                        word + '!',
                        word + '123!',
                        word + '2023',
                        word + '1',
                    ]

                    for variation in variations:
                        if self._hash(variation) == target_hash:
                            self.found = True
                            self.result = variation
                            break

                    # Update stats every 1000 words
                    if self.tested % 1000 == 0:
                        self._update_stats(1000)
                        self._print_progress()

            self._update_stats(self.tested % 1000)  # Update remaining
            self._print_progress()
            print()  # New line after progress

        except Exception as e:
            print(f"[-] Error during dictionary attack: {str(e)}")
            return None

        return self.result

    def brute_force_attack(self, target_hash: str, max_length: int = 8, 
                         charset: str = string.printable.strip()) -> Optional[str]:
        """Optimized brute force attack with progress tracking"""
        # First try Hashcat if GPU is enabled
        if self.use_gpu:
            charset_arg = f'?a' if charset == string.printable.strip() else f'-1 {charset}'
            mask = f'{charset_arg}{{1,{max_length}}}'
            if result := self._try_hashcat(target_hash, '3', mask):
                return result

        def worker():
            while not self.queue.empty() and not self.found:
                length = self.queue.get()
                for candidate in itertools.product(charset, repeat=length):
                    if self.found:
                        self.queue.task_done()
                        return

                    candidate_str = ''.join(candidate)
                    if self._hash(candidate_str) == target_hash:
                        with self.lock:
                            self.found = True
                            self.result = candidate_str
                        self.queue.task_done()
                        return

                    # Update stats
                    with self.lock:
                        self.tested += 1
                        if self.tested % 1000 == 0:
                            self._print_progress()

                self.queue.task_done()

        # Fill queue with lengths to try
        for length in range(1, max_length + 1):
            self.queue.put(length)

        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)

        # Progress monitor
        def progress_monitor():
            while any(t.is_alive() for t in threads):
                self._print_progress()
                time.sleep(0.1)

        monitor = threading.Thread(target=progress_monitor)
        monitor.start()

        for t in threads:
            t.join()

        monitor.join()
        print()  # New line after progress

        return self.result

    def rule_based_attack(self, target_hash: str, wordlist_path: str, rules_file: str = '/usr/share/hashcat/rules/best64.rule') -> Optional[str]:
        """Perform rule-based attack using Hashcat rules"""
        if not os.path.exists(rules_file):
            print(f"[-] Rules file not found: {rules_file}")
            return None

        if self.use_gpu:
            if result := self._try_hashcat(target_hash, '0', f'{wordlist_path} -r {rules_file}'):
                return result

        print("[-] Rule-based attack requires Hashcat in this implementation")
        return None

def main():
    parser = argparse.ArgumentParser(
        description="Kali Linux Advanced Hashed Password Cracker",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("hash", help="The hash to crack")
    parser.add_argument("hash_type", help="Hash algorithm (md5, sha1, sha256, ntlm, etc.)")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist file for dictionary attack")
    parser.add_argument("-b", "--bruteforce", action="store_true", help="Use brute force attack")
    parser.add_argument("-l", "--length", type=int, default=8, help="Max length for brute force attack")
    parser.add_argument("-c", "--charset", default=string.printable.strip(), 
                       help="Character set for brute force attack")
    parser.add_argument("-r", "--rules", help="Path to Hashcat rules file for rule-based attack")
    parser.add_argument("-g", "--gpu", action="store_true", help="Use GPU acceleration (Hashcat)")
    parser.add_argument("-t", "--threads", type=int, help="Number of threads to use (default: auto-detect)")
    parser.add_argument("-d", "--distributed", help="JSON config file for distributed cracking")
    args = parser.parse_args()

    print("[*] Starting password cracking session")
    print(f"[*] Target hash: {args.hash}")
    print(f"[*] Hash type: {args.hash_type}")
    if args.gpu:
        print("[*] GPU acceleration: Enabled" if HASHCAT_AVAILABLE else "[-] GPU acceleration: Hashcat not found")

    try:
        cracker = KaliPasswordCracker(args.hash_type, args.threads, args.gpu)
    except ValueError as e:
        print(f"[-] {str(e)}")
        return

    result = None
    start_time = time.time()

    # Distributed cracking setup (if configured)
    if args.distributed:
        try:
            import json
            with open(args.distributed) as f:
                nodes = json.load(f)
            dist_cracker = DistributedCracker(nodes)
            print(f"[*] Distributed cracking with {len(nodes)} nodes")
        except Exception as e:
            print(f"[-] Failed to initialize distributed cracking: {str(e)}")

    # Attack selection
    if args.wordlist and args.rules:
        print("[*] Starting rule-based attack...")
        result = cracker.rule_based_attack(args.hash, args.wordlist, args.rules)
    elif args.wordlist:
        print("[*] Starting dictionary attack...")
        result = cracker.dictionary_attack(args.hash, args.wordlist)
    elif args.bruteforce:
        print("[*] Starting brute force attack...")
        result = cracker.brute_force_attack(args.hash, args.length, args.charset)
    else:
        print("[-] Please specify an attack method (--wordlist, --bruteforce, or --rules)")

    if result:
        print(f"\n[+] Password cracked: {result}")
    else:
        print("\n[-] Password not found")

    elapsed = time.time() - start_time
    print(f"\n[*] Total time: {elapsed:.2f} seconds")
    if cracker.tested > 0:
        print(f"[*] Total tested: {cracker.tested:,}")
        print(f"[*] Average rate: {cracker.tested/elapsed:,.0f} hashes/sec")

if __name__ == "__main__":
    main()
