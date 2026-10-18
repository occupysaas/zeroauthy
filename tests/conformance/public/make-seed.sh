#!/usr/bin/env bash
# tests/conformance/public/make-seed.sh: render the hosted certification kit.
#
#   ./tests/conformance/public/make-seed.sh HOST ALIAS OUTDIR
#
#   HOST    the public hostname zeroauthy serves, e.g. auth.turbojobapply.com
#   ALIAS   the hosted suite's alias, e.g. zeroauthy (callbacks are
#           https://www.certification.openid.net/test/a/ALIAS/callback)
#   OUTDIR  where to write; must be outside the repository
#
# Writes OUTDIR/seed.yaml, OUTDIR/configs/{basic,config,formpost,logout}.json
# and OUTDIR/secrets.txt, with fresh random client secrets and a fresh user
# password. The hosted suite publishes its logs, so these secrets are
# throwaway: never reuse them and never commit the output.
set -euo pipefail

usage() { echo "usage: $0 HOST ALIAS OUTDIR" >&2; exit 2; }
[[ $# -eq 3 ]] || usage
host="$1" alias="$2" out="$3"

here="$(cd "$(dirname "$0")" && pwd -P)"
repo="$(cd "$here/../../.." && pwd -P)"

# A bare DNS name (no scheme, port or path): the issuer is https://HOST/.
if [[ ! "$host" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]]; then
  echo "HOST must be a DNS name such as auth.example.com (no scheme, port or path), not '$host'" >&2
  exit 2
fi
host="${host,,}"
if [[ ! "$alias" =~ ^[A-Za-z0-9_-]+$ ]]; then
  echo "ALIAS may contain only letters, digits, '-' and '_', not '$alias'" >&2
  exit 2
fi
for tool in openssl python3; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }
done

# OUTDIR must not be inside the repository (or be the repository itself).
out_abs="$(realpath -m -- "$out")"
case "$out_abs/" in
  "$repo"/*)
    echo "refusing to write secrets inside the repository ($repo): choose an OUTDIR outside it" >&2
    exit 1
    ;;
esac
for f in seed.yaml secrets.txt configs; do
  if [[ -e "$out_abs/$f" ]]; then
    echo "$out_abs/$f already exists; refusing to overwrite a rendered kit (delete it or pick another OUTDIR)" >&2
    exit 1
  fi
done

umask 077
mkdir -p "$out_abs/configs"

# Hex keeps the values safe in YAML and JSON. The password prefix adds
# an upper-case letter and a symbol for the default password policy.
client1_secret="$(openssl rand -hex 32)"
client2_secret="$(openssl rand -hex 32)"
client_post_secret="$(openssl rand -hex 32)"
user_password="Za-$(openssl rand -hex 12)"

# The secrets reach the substitution through the environment of one child
# process, never its command line, so they do not show up in ps.
render() {
  ZA_HOST="$host" ZA_ALIAS="$alias" ZA_CLIENT1_SECRET="$client1_secret" \
    ZA_CLIENT2_SECRET="$client2_secret" ZA_CLIENT_POST_SECRET="$client_post_secret" \
    ZA_USER_PASSWORD="$user_password" python3 -I - "$1" "$2" <<'PY'
import os, sys
src, dst = sys.argv[1:]
text = open(src).read()
for name in ("HOST", "ALIAS", "CLIENT1_SECRET", "CLIENT2_SECRET", "CLIENT_POST_SECRET", "USER_PASSWORD"):
    text = text.replace("@@" + name + "@@", os.environ["ZA_" + name])
with open(dst, "w") as f:
    f.write(text)
PY
  if grep -q '@@[A-Z0-9_]*@@' "$2"; then
    echo "unreplaced placeholder in $2" >&2
    exit 1
  fi
}

render "$here/seed.yaml.tmpl" "$out_abs/seed.yaml"
for p in basic config formpost logout; do
  render "$here/configs/$p.json.tmpl" "$out_abs/configs/$p.json"
done

cat >"$out_abs/secrets.txt" <<EOF
# zeroauthy hosted certification kit, generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Throwaway values: the hosted suite publishes its logs. Never commit this.
host=$host
issuer=https://$host/
alias=$alias
callback=https://www.certification.openid.net/test/a/$alias/callback
post_logout_redirect=https://www.certification.openid.net/test/a/$alias/post_logout_redirect
za-cert-1 (client_secret_basic)=$client1_secret
za-cert-2 (client_secret_basic)=$client2_secret
za-cert-post (client_secret_post)=$client_post_secret
user conformance@example.com password=$user_password
EOF

echo "wrote the certification kit to $out_abs:"
echo "  $out_abs/seed.yaml        (zeroauthy seed: copy to the server)"
echo "  $out_abs/configs/*.json   (paste into each hosted test plan)"
echo "  $out_abs/secrets.txt      (the generated secrets; keep private until teardown)"
