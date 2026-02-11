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
  mkdir -p "$TD/recon" "$TD/vulns"

  cd "$TD/recon"

  echo "[*] Subfinder: $TARGET"
  subfinder -d "$TARGET" -all -silent -o subfinder.txt || true

  echo "[*] httpx live hosts"
  cat subfinder.txt | httpx -silent -sc -cl -title -tech-detect -o livefull.txt || true
  cat livefull.txt | awk '{print $1}' | sort -u > liveurls.txt || true

  echo "[*] waybackurls + gau"
  cat liveurls.txt | waybackurls | sort -u > waybackurls.txt || true
  cat liveurls.txt | gau --threads 3 --subs | sort -u > gauurls.txt || true

  echo "[*] combine + uro"
  cat waybackurls.txt gauurls.txt | uro | sort -u > allurls.txt || true

  echo "[*] param urls + gf"
  grep '?' allurls.txt | sort -u > paramurls.txt || true
  cat paramurls.txt | gf xss   > gfxss.txt   || true
  cat paramurls.txt | gf sqli  > gfsqli.txt  || true
  cat paramurls.txt | gf ssrf  > gfssrf.txt  || true
  cat paramurls.txt | gf idor  > gfidor.txt  || true

  cd "$TD/vulns"

  echo "[*] nuclei lite"
  nuclei -l ../recon/liveurls.txt \
    -severity critical,high,medium \
    -rate-limit 20 -c 10 \
    -o nuclei.txt || true

  echo "[*] dalfox on gfxss"
  if [ -s ../recon/gfxss.txt ]; then
    cat ../recon/gfxss.txt | dalfox pipe --silence -w 30 -o xss_dalfox.txt || true
  fi

  echo "Done for $TARGET"
  cd -
done < targets.txt

echo "[*] Recon finished, results in $OUTDIR"
