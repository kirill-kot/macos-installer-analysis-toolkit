#!/bin/bash
# auto_full_installer_scan.sh — complete autonomous macOS installers search and analysis
# Fully self-contained: finds installers, analyses Mach-O, shell scripts, Base64/XOR, strings, suspicious commands

# --- 0. Ask for folder to scan ---
read -p "Please specify path to search installers (Enter for /Volumes/): " TARGET_DIR
TARGET_DIR=${TARGET_DIR:-/Volumes}

echo "[*] Scanning folder: $TARGET_DIR"

# --- 1. Search installers ---
INSTALLERS=$(find "$TARGET_DIR" -maxdepth 2 -type f \( -name ".Installer*" -o -name "Installer.ohH" -o -name "Installer.RuJ" -o -name "*.orig" \))

if [ -z "$INSTALLERS" ]; then
    echo "[!] No installers found in $TARGET_DIR. Checking all mounted drives..."
    INSTALLERS=$(find /Volumes -maxdepth 2 -type f \( -name ".Installer*" -o -name "Installer.ohH" -o -name "Installer.RuJ" -o -name "*.orig" \))
fi

if [ -z "$INSTALLERS" ]; then
    echo "[!] No installers found in specified folder or /Volumes/"
    exit 1
fi

# --- 2. Create root analysis folder ---
mkdir -p analysis
echo "[*] Installers found:"
echo "$INSTALLERS"

# --- 3. Iterate over found files ---
for FILE in $INSTALLERS; do
    # --- Skip if not a regular file ---
    if [ ! -f "$FILE" ]; then
        echo "[!] Skipping non-regular file: $FILE"
        continue
    fi

    BASENAME=$(basename "$FILE")
    ANALYSIS_DIR="analysis/$BASENAME"
    mkdir -p "$ANALYSIS_DIR"
    echo "[*] Analysing: $FILE"
    echo "[*] Analysis folder: $ANALYSIS_DIR"

    # --- 3a. File type ---
    echo "[*] File type:" | tee "$ANALYSIS_DIR/file.txt"
    file "$FILE" | tee -a "$ANALYSIS_DIR/file.txt"

    # --- 3b. Mach-O analysis ---
    if file "$FILE" | grep -q "Mach-O"; then
        echo "[*] This is a Mach-O binary"
        echo "[*] lipo info:" | tee -a "$ANALYSIS_DIR/macho_info.txt"
        lipo -info "$FILE" | tee -a "$ANALYSIS_DIR/macho_info.txt"
        echo "[*] otool header:" | tee -a "$ANALYSIS_DIR/macho_info.txt"
        otool -hv "$FILE" | tee -a "$ANALYSIS_DIR/macho_info.txt"
        echo "[*] otool linked libs:" | tee -a "$ANALYSIS_DIR/macho_info.txt"
        otool -L "$FILE" | tee -a "$ANALYSIS_DIR/macho_info.txt"
        echo "[*] otool segments:" | tee -a "$ANALYSIS_DIR/macho_info.txt"
        otool -l "$FILE" | tee -a "$ANALYSIS_DIR/macho_info.txt"
        otool -s __TEXT __cstring "$FILE" > "$ANALYSIS_DIR/segments__cstring.txt"
        otool -s __DATA __data "$FILE" > "$ANALYSIS_DIR/segments__data.txt"
    fi

    # --- 3c. All printable strings ---
    strings "$FILE" | awk 'length($0)>=20' > "$ANALYSIS_DIR/printable.txt"

    # --- 3d. Suspicious commands / URL ---
    strings "$FILE" | egrep -i "http|https|curl|wget|dd|diskutil|asr|launchctl|chmod|chown|/tmp|/var|ssh|/Library" | sort | uniq > "$ANALYSIS_DIR/suspicious.txt"

    # --- 3e. Base64-ish candidates ---
    strings "$FILE" | egrep '[A-Za-z0-9+/=]{40,}' > "$ANALYSIS_DIR/b64_candidates.txt"

    # --- 3f. SHA256 ---
    shasum -a 256 "$FILE" > "$ANALYSIS_DIR/sha256.txt"

    # --- 3g. Shell script extraction (optional) ---
    if file "$FILE" | grep -q "shell script"; then
        if [ -f extract.py ]; then
            echo "[*] Launching extract.py..."
            python3 extract.py "$FILE" "$ANALYSIS_DIR"
        fi
        if [ -f extract2.py ]; then
            echo "[*] Launching extract2.py..."
            python3 extract2.py "$FILE" "$ANALYSIS_DIR"
        fi
    fi

    # --- 3h. Auto Base64 + XOR decoding ---
    B64_PAYLOAD="$ANALYSIS_DIR/b64_candidates.txt"
    DECODE_DIR="$ANALYSIS_DIR/decoded"
    mkdir -p "$DECODE_DIR"

    DECODED_B64="$DECODE_DIR/decoded_payload_base64.bin"
    > "$DECODED_B64"
    echo "[*] Decoding Base64 candidates..."
    if [ -f "$B64_PAYLOAD" ]; then
        while read -r line; do
            echo "$line" | base64 --decode 2>/dev/null >> "$DECODED_B64"
        done < "$B64_PAYLOAD"
    fi

    # --- 3i. XOR keys ---
    XOR_KEYS_HEX=($(grep -Eo 'pack\("H\*",\s*"([0-9a-fA-F]+)' "$FILE" | sed -E 's/.*"([0-9a-fA-F]+)$/\1/'))

    if [ ${#XOR_KEYS_HEX[@]} -eq 0 ]; then
        echo "[!] XOR keys not found, using default key"
        XOR_KEYS_HEX=("5dfc55d70115a405ce6557e7fc77befb")
    fi

    # Applying each key
    for KEY_HEX in "${XOR_KEYS_HEX[@]}"; do
        FINAL_BIN="$DECODE_DIR/decoded_payload_${KEY_HEX}.bin"
        echo "[*] Applying XOR decode with key $KEY_HEX..."
        python3 - <<EOF
import binascii
key = binascii.unhexlify("$KEY_HEX")
with open("$DECODED_B64", "rb") as f:
    data = f.read()
decoded = bytearray([data[i] ^ key[i % len(key)] for i in range(len(data))])
with open("$FINAL_BIN", "wb") as out:
    out.write(decoded)
EOF
    done

    echo "[*] XOR-decoded payload ready in $DECODE_DIR"
    echo "--------------------------------------------"
done

echo "[*] All found installers analysed."
