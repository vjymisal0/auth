#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE_URL="${GOTRUE_URL:-http://localhost:9999}"
SECRET="${GOTRUE_JWT_SECRET:-$(sed -n 's/^GOTRUE_JWT_SECRET=//p' "$ROOT/.env" 2>/dev/null | tr -d '"')}"
RUN="$(date +%s)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

[ -n "$SECRET" ] || { echo "set GOTRUE_JWT_SECRET or add it to $ROOT/.env" >&2; exit 1; }

b64url() {
  openssl base64 -e -A | tr '+/' '-_' | tr -d '='
}

admin_jwt() {
  local now header payload sig
  now="$(date +%s)"
  header="$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | b64url)"
  payload="$(printf '{"role":"service_role","iat":%s,"exp":%s}' "$now" "$((now + 600))" | b64url)"
  sig="$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -hmac "$SECRET" -binary | b64url)"
  printf '%s.%s.%s' "$header" "$payload" "$sig"
}

ADMIN_TOKEN="$(admin_jwt)"

call() {
  local expected="$1" method="$2" url="$3" token="$4" body="${5:-}" status
  local args=(-s -X "$method" -o "$TMP/body" -w '%{http_code}' -H "Authorization: Bearer $token")
  [ -n "$body" ] && args+=(-H 'Content-Type: application/scim+json' --data "$body")
  printf '\n\033[1m%s %s\033[0m\n' "$method" "${url#"$BASE_URL"}"
  status="$(curl "${args[@]}" "$url")"
  [ -s "$TMP/body" ] && jq -C . < "$TMP/body"
  if [ "$status" != "$expected" ]; then
    printf '\033[1;31mHTTP %s, expected %s\033[0m\n' "$status" "$expected"
    exit 1
  fi
  printf '\033[1;32mHTTP %s\033[0m\n' "$status"
}

field() {
  jq -r "$1" < "$TMP/body"
}

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TMP/key.pem" -subj "/CN=scim-demo.example" -days 1 -outform DER -out "$TMP/cert.der" 2>/dev/null
CERT="$(openssl base64 -e -A < "$TMP/cert.der")"
METADATA="<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"https://scim-demo-$RUN.example/entityid\"><md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>$CERT</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://scim-demo-$RUN.example/sso\"/></md:IDPSSODescriptor></md:EntityDescriptor>"

call 201 POST "$BASE_URL/admin/sso/providers" "$ADMIN_TOKEN" "$(jq -n --arg xml "$METADATA" '{type: "saml", metadata_xml: $xml}')"
PROVIDER="$(field .id)"
ADMIN="$BASE_URL/admin/sso/providers/$PROVIDER"

call 200 POST "$ADMIN/scim" "$ADMIN_TOKEN"
call 201 POST "$ADMIN/scim/tokens" "$ADMIN_TOKEN" '{}'
SCIM_TOKEN="$(field .token)"
SCIM="$BASE_URL/scim/v2"

call 200 GET "$SCIM/ServiceProviderConfig" "$SCIM_TOKEN"

USERNAME="bjensen+$RUN@example.com"
call 201 POST "$SCIM/Users" "$SCIM_TOKEN" "{
  \"schemas\": [\"urn:ietf:params:scim:schemas:core:2.0:User\"],
  \"userName\": \"$USERNAME\",
  \"name\": {\"givenName\": \"Barbara\", \"familyName\": \"Jensen\"},
  \"emails\": [{\"value\": \"$USERNAME\", \"primary\": true}],
  \"active\": true
}"
USER="$(field .id)"

call 200 GET "$SCIM/Users?filter=$(jq -rn --arg f "userName eq \"$USERNAME\"" '$f | @uri')" "$SCIM_TOKEN"

call 200 PATCH "$SCIM/Users/$USER" "$SCIM_TOKEN" '{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [{"op": "replace", "path": "name.familyName", "value": "Jensen-Smith"}]
}'

call 201 POST "$SCIM/Groups" "$SCIM_TOKEN" "{
  \"schemas\": [\"urn:ietf:params:scim:schemas:core:2.0:Group\"],
  \"displayName\": \"Tour Guides $RUN\",
  \"members\": [{\"value\": \"$USER\"}]
}"
GROUP="$(field .id)"

call 200 PATCH "$SCIM/Users/$USER" "$SCIM_TOKEN" '{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [{"op": "replace", "path": "active", "value": false}]
}'

call 204 DELETE "$SCIM/Groups/$GROUP" "$SCIM_TOKEN"
call 204 DELETE "$SCIM/Users/$USER" "$SCIM_TOKEN"
call 404 GET "$SCIM/Users/$USER" "$SCIM_TOKEN"

call 200 DELETE "$ADMIN/scim" "$ADMIN_TOKEN"
call 401 GET "$SCIM/Users" "$SCIM_TOKEN"
call 200 DELETE "$ADMIN" "$ADMIN_TOKEN"
