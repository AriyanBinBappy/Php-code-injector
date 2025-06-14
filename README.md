# Octo Dark Cyber Squad PHP Injector Tool



## 🛠️ Overview

The **Octo Dark Cyber Squad PHP Injector Tool** allows security testers and researchers to stealthily embed PHP payloads into JPEG image metadata. This can be used for advanced authorized penetration testing and security research.

Inject PHP webshells or arbitrary PHP code into multiple JPEG metadata fields, including EXIF, IPTC, and XMP — enabling covert payload delivery in environments that rely on image uploads.

---

## ⚙️ Features

- **Multiple Injection Methods:**
  - EXIF UserComment
  - EXIF ImageDescription
  - IPTC Caption
  - XMP Description

- **Null Byte Injection:**  
  Add a terminating null byte to bypass simple PHP filtering.

- **Extraction Support:**  
  Extract PHP payloads from EXIF UserComment and ImageDescription fields.

- **Error Handling:**  
  Robust handling with descriptive error messages for safer usage.

- **Interactive CLI:**  
  User-friendly menu to select injection or extraction modes.

---

## 🚀 Usage

1. **Run the tool:**

   ```bash
   python php_injector.py
   ```

2. **Select Mode:**

   - `1` to Inject PHP payload
   - `2` to Extract from EXIF UserComment
   - `3` to Extract from EXIF ImageDescription

3. **Follow prompts to specify image paths, payloads, and injection methods.**

---

## 🔧 Injection Methods Explained

| Method             | Description                             | Notes                        |
|--------------------|---------------------------------------|------------------------------|
| `usercomment`      | Injects into EXIF UserComment field    | Supports null byte injection  |
| `imagedescription` | Injects into EXIF ImageDescription     | Supports null byte injection  |
| `iptc`             | Injects into IPTC Caption block        | Direct binary append          |
| `xmp`              | Injects into XMP Description packet    | Embedded as APP1 segment      |

---

## ⚠️ Disclaimer

- **Authorized Use Only:** This tool is intended strictly for authorized security testing and research.
- **Legal Warning:** Unauthorized use against systems without permission is illegal and unethical.
- Use responsibly and obtain proper authorization before testing any systems.

---

## 📦 Requirements

- Python 3.6+
- [`piexif`](https://pypi.org/project/piexif/) library  
  Install via pip:  
  ```bash
  pip install piexif
  ```

---

## 🔍 Example Payload

Default webshell payload used when none specified:

```php
<?php if(isset($_GET['cmd'])){system($_GET['cmd']);} ?>
```

---

## 📈 Future Improvements

- Add extraction for IPTC and XMP metadata
- UTF-8 payload support
- CLI argument mode for automation
- Support for more metadata fields
- Payload validation and verification tools

---

## 👤 Author & Contact

**Ariyan Bin Bappy**  
Octo Dark Cyber Squad  
GitHub: [https://github.com/AriyanBinBappy](https://github.com/AriyanBinBappy)  

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
