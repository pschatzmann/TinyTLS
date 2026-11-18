#!/bin/sh
# Creates the PKI and signed test messages used by the X.509 and signature tests.
# Usage: make_test_pki.sh <output-directory>
set -e
OUT="$1"
mkdir -p "$OUT"
cd "$OUT"
EXT_CA="basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign"
EXT_INT="basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign"
EXT_LEAF="basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
subjectAltName=DNS:localhost,DNS:*.example.test"
printf '%s\n' "$EXT_CA" > ca.cnf
printf '%s\n' "$EXT_INT" > int.cnf
printf '%s\n' "$EXT_LEAF" > leaf.cnf

# EC chain: root -> intermediate -> leaf
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout ec_root.key -out ec_root.pem -days 3650 -subj "/CN=TinyTLS EC Root" -config /dev/null \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ec_int.key \
  -out ec_int.csr -subj "/CN=TinyTLS EC Intermediate" 2>/dev/null
openssl x509 -req -in ec_int.csr -CA ec_root.pem -CAkey ec_root.key -CAcreateserial \
  -out ec_int.pem -days 3000 -extfile int.cnf 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ec_leaf.key \
  -out ec_leaf.csr -subj "/CN=localhost" 2>/dev/null
openssl x509 -req -in ec_leaf.csr -CA ec_int.pem -CAkey ec_int.key -CAcreateserial \
  -out ec_leaf.pem -days 30 -extfile leaf.cnf 2>/dev/null
# Leaf valid for 30 days only: tests for expiry use a time after notAfter.
cat ec_leaf.pem ec_int.pem > ec_leaf_chain.pem

# RSA chain: root -> leaf
openssl req -x509 -newkey rsa:2048 -nodes -keyout rsa_root.key -out rsa_root.pem -days 3650 \
  -subj "/CN=TinyTLS RSA Root" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout rsa_leaf.key -out rsa_leaf.csr -subj "/CN=localhost" 2>/dev/null
openssl x509 -req -in rsa_leaf.csr -CA rsa_root.pem -CAkey rsa_root.key -CAcreateserial \
  -out rsa_leaf.pem -days 30 -extfile leaf.cnf 2>/dev/null

# Unrelated trust anchor for negative tests.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout evil.key \
  -out evil_root.pem -days 3650 -subj "/CN=Evil Root" \
  -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null

# Signed message for CertificateVerify-style signature tests.
printf 'tinytls signature test message' > msg.bin
openssl dgst -sha256 -sign ec_leaf.key -out ec_sig.der msg.bin
openssl dgst -sha256 -sign rsa_leaf.key -out rsa_pkcs1_sig.bin msg.bin
openssl dgst -sha256 -sign rsa_leaf.key -sigopt rsa_padding_mode:pss \
  -sigopt rsa_pss_saltlen:32 -out rsa_pss_sig.bin msg.bin
# Public keys in SPKI DER form.
openssl pkey -in ec_leaf.key -pubout -outform DER -out ec_leaf_spki.der
openssl pkey -in rsa_leaf.key -pubout -outform DER -out rsa_leaf_spki.der
echo "PKI ready in $OUT"
