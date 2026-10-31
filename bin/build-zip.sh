#!/usr/bin/env bash
# Construit build/graphin-simple-security-ssl.zip sans les fichiers de développement (.distignore).
# Utilisé par la GitHub Action de release, et en local pour contrôler le zip avant un tag.
set -euo pipefail

SLUG=graphin-simple-security-ssl
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/build"

rm -rf "$BUILD"
mkdir -p "$BUILD/$SLUG"
rsync -a --exclude-from="$ROOT/.distignore" "$ROOT/" "$BUILD/$SLUG/"

# Garde-fous : la librairie de mise à jour doit être là, aucun outil de dev ne doit l'être.
test -f "$BUILD/$SLUG/vendor/plugin-update-checker/plugin-update-checker.php"
test -f "$BUILD/$SLUG/uninstall.php"
while read -r forbidden; do
	if [ -n "$forbidden" ] && [ -e "$BUILD/$SLUG/$forbidden" ]; then
		echo "Fichier de dev présent dans le zip : $forbidden" >&2
		exit 1
	fi
done < "$ROOT/.distignore"

(cd "$BUILD" && zip -rq "$SLUG.zip" "$SLUG")
echo "$BUILD/$SLUG.zip"
