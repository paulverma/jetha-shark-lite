#!/usr/bin/env bash
set -e

DATE=$(date +%Y-%m-%d_%H-%M)
OUTDIR="results/$DATE"
mkdir -p "$OUTDIR"

echo "[*] Starting recon at $DATE"

while read -r TARGET; do
  [ -z "$TARGET" ] && continue
  echo "===== TARGET: $TARGET ====="

  SAFE_TARGET=$(echo "$TARGET" | tr '/:' '_')
  TD="$OUTDIR/$SAFE_TARGET"

  # Make sure both dirs always exist
  mkdir -p "$TD/recon"
  mkdir -p "$TD/vulns"

  # --- RECON PART ---
  cd "$TD/recon"

  echo "[*] Subfinder: $TARGET"
  subfinder -d "$TARGET" -all -silent -o subfinder.txt || true

  echo "[*] httpx live hosts"
  cat subfinder.txt | httpx -silent -sc -cl -title -tech-detect -rl 50 -o livefull.txt || true
  cat livefull.txt | awk '{print $1}' | sort -u > liveurls.txt || true

  echo "[*] waybackurls only (no gau)"
  cat liveurls.txt | waybackurls | sort -u > waybackurls.txt || true

  echo "[*] combine + uro"
  cat waybackurls.txt | uro | sort -u > allurls.txt || true

  echo "[*] param urls + gf"
  grep '?' allurls.txt | sort -u > paramurls.txt || true
  cat paramurls.txt | gf xss   > gfxss.txt   || true
  cat paramurls.txt | gf sqli  > gfsqli.txt  || true
  cat paramurls.txt | gf ssrf  > gfssrf.txt  || true
  cat paramurls.txt | gf idor  > gfidor.txt  || true

  cd - >/dev/null 2>&1

  # --- VULNS PART ---
  cd "$TD/vulns"

  echo "[*] nuclei lite"
  nuclei -l ../recon/liveurls.txt \
    -severity critical,high,medium \
    -rate-limit 15 -c 5 \
    -o nuclei.txt || true

  echo "[*] dalfox on gfxss (low threads)"
  if [ -s ../recon/gfxss.txt ]; then
    cat ../recon/gfxss.txt | dalfox pipe --silence -w 10 -o xss_dalfox.txt || true
  fi

  echo "Done for $TARGET"
  cd - >/dev/null 2>&1
done < targets.txt

echo "[*] Recon finished, results in $OUTDIR"
