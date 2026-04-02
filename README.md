# cam_probe

**cam_probe** is a defensive research tool by [Sebastian van de Meer](https://www.kernel-error.de).  
It helps you check your **own IP cameras** (in lab or private networks) for **publicly accessible HTTP endpoints** —  
for example, unprotected JPG snapshots or MJPEG streams that can be accessed without authentication.

> ⚠️ This tool is strictly meant for authorized security testing on systems you own or have explicit permission to test.

---

## 🌟 Features

- Scans a wide range of common camera URL paths (HTTP/S)
- Detects real image content (JPEG, PNG, MJPEG)
- Multithreaded and fast, with adjustable worker count
- Supports timeout, custom path lists, and custom User-Agent headers
- **No login attempts**, **no RTSP**, and **no exploits**
- Results are stored in structured folders with CSV logs and any found images

---

## 🚀 Quick Start

Run it directly from the command line:

```bash
python3 cam_probe.py -H 192.168.0.10 -p 88
```

### More examples:

```bash
python3 cam_probe.py -H 192.0.2.10 -p 88
python3 cam_probe.py -H 198.51.100.5 --ports 80,81,88,8080 -w 32 -t 10
python3 cam_probe.py -H 203.0.113.7 -p 81 --paths-file camera_paths_mega.txt
python3 cam_probe.py -H 192.168.1.5 -p 443 --scheme https --no-verify-ssl
python3 cam_probe.py -H 192.168.1.5 -p 80 --skip-head --delay 0.3
```

---

## ⚙️ Installation

Python 3.8 or newer is recommended.  
Install dependencies via:

```bash
pip install -r requirements.txt
```

or manually:

```bash
pip install requests
```

---

## 🧩 Command-Line Options

```text
-H, --host            Target IPv4 address (only devices you own)
-p, --port            Port to scan (e.g., 80 or 88)
--ports               Comma-separated list of multiple ports
--scheme              http or https
-w, --workers         Number of concurrent threads (default: 24)
-t, --timeout         Request timeout in seconds (default: 8.0)
--max-bytes           Max bytes to read per response (default: 512 KB)
--paths-file          Custom file with additional camera paths
--user-agent          Custom User-Agent header
--skip-head           Skip HEAD preflight, go directly to GET
--no-verify-ssl       Disable TLS cert verification (self-signed certs)
--delay               Avg delay between requests per worker (default: 0.15s)
```

---

## 🧠 Example Output

```text
[200] http://192.168.0.10:88/cgi-bin/snapshot.cgi (ct=image/jpeg) [IMAGE FOUND]
[404] http://192.168.0.10:88/snapshot.jpg (ct=text/html) [no_image_detected]
[+] Done. Results written to cam_probe_192.168.0.10_88/results.csv
```

---

## 🧩 Requirements

- Python ≥ 3.8  
- requests ≥ 2.31.0

---

## 🧪 Testing

```bash
pytest test_cam_probe.py -v
```

92 tests covering all core logic. All HTTP interactions are mocked — no network access or camera required.

---

## 🧑‍💻 Author & License

**Author:** [Sebastian van de Meer](https://www.kernel-error.de)  
**License:** [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/)

You are free to use, modify, and share this tool for any purpose — as long as you **credit the author** by name and link.

---

## ❤️ Contributing

Feel free to submit pull requests, improvements, or additional camera path lists.  
Every contribution that helps secure devices is welcome!

---

## 🛡️ Disclaimer

This tool is intended for **defensive research and private security auditing only**.  
Do **not** use it to access or probe systems without explicit authorization.  
Unauthorized testing may be illegal in your country.
