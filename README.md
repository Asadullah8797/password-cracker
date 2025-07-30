# 🔐 Advanced Password Cracker

A powerful Python-based tool for cracking hashed passwords using multiple techniques including **brute-force**, **dictionary attacks**, **rule-based mutations**, **GPU acceleration**, and **distributed cracking**.

> ✅ Made for cybersecurity research, CTFs, and ethical hacking training.

---

## 🚀 Features

- 🧠 Brute Force Cracking
- 📚 Dictionary Attack
- 🔁 Rule-Based Attack (like Hashcat rules)
- 🚀 GPU Acceleration (via Hashcat)
- 🌐 Distributed Cracking with config file
- 🔢 Multithreading Support
- 🧪 Supports popular hash types: `md5`, `sha1`, `sha256`, `ntlm`, etc.

---

## 🛠️ Installation

> 🐍 Requires **Python 3.x**

```bash
git clone https://github.com/Asadullah8797/password-cracker.git
cd password-cracker
pip install -r requirements.txt  # Only if you use any libraries




🧠 How to Use
Use the appropriate mode based on your attack method.

1️⃣ Brute Force Attack
bash
Copy
Edit
python3 advanced_cracker.py <hash> <hash_type> -b -c <charset> -l <max_length>
Example:

bash
Copy
Edit
python3 advanced_cracker.py e99a18c428cb38d5f260853678922e03 md5 -b -c abc123 -l 6
-b: Enable brute force mode

-c: Charset to use (e.g., abc123)

-l: Max password length to try

2️⃣ Dictionary Attack
bash
Copy
Edit
python3 advanced_cracker.py <hash> <hash_type> -w /path/to/wordlist.txt
Example:

bash
Copy
Edit
python3 advanced_cracker.py e99a18c428cb38d5f260853678922e03 md5 -w wordlists/rockyou.txt
3️⃣ Rule-Based Attack (with wordlist)
bash
Copy
Edit
python3 advanced_cracker.py <hash> <hash_type> -w /path/to/wordlist.txt -r /path/to/rules.rule
Rules file can define how to mutate words (e.g., capitalize, reverse, add numbers, etc.)

4️⃣ GPU Acceleration (Experimental)
bash
Copy
Edit
python3 advanced_cracker.py <hash> <hash_type> -b -g -c abc123 -l 6
-g: Enable GPU acceleration (Hashcat must be installed)

5️⃣ Distributed Cracking (Multiple Systems)
bash
Copy
Edit
python3 advanced_cracker.py <hash> <hash_type> -d config.json
-d: JSON config file that splits task across multiple nodes

📜 View All Options
bash
Copy
Edit
python3 advanced_cracker.py --help
You will see all available flags and examples.

🔓 Supported Hash Types
This tool supports the following hash types:

md5

sha1

sha256

ntlm

You can extend it further by modifying the code.

🧾 Project Structure
bash
Copy
Edit
password-cracker/
├── advanced_cracker.py        # Main tool
├── README.md                  # You are here
├── wordlists/                 # Add your dictionaries
├── rules/                     # Rule files (optional)
└── config/                    # JSON config for distributed attack
📸 Example Output
less
Copy
Edit
[+] Starting password cracking session
[+] Target hash: e99a18c428cb38d5f260853678922e03
[+] Hash type: md5
[+] Starting brute force attack...
[+] Tested: 11,195 | Cracked Password: abc123
[+] Total time: 0.01 seconds
⚠️ Disclaimer
This tool is developed for educational and ethical testing purposes only.
Using it on unauthorized systems is illegal. Use responsibly and only where you have permission.

🙋 Author
Asadullah Galib
GitHub: Asadullah8797
