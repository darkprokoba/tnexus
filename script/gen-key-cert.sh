#!/bin/bash

CERTDIR=`dirname "${BASH_SOURCE[0]}"`/../ssl
mkdir -p "$CERTDIR"
cd "$CERTDIR"
CERTDIR=`pwd`

echo "Generating keys and certs into folder: $CERTDIR"

openssl req -x509 -sha256 -nodes -days 3650 -newkey rsa:2048 \
	-subj "/C=BG/ST=Sofia/L=Sofia/O=tnexus/OU=server/CN=tnexus.net"\
	-keyout "$CERTDIR"/api_key.pem \
	-out "$CERTDIR"/api_cert.pem

openssl req -x509 -sha256 -nodes -days 3650 -newkey rsa:2048 \
	-subj "/C=BG/ST=Sofia/L=Sofia/O=tnexus/OU=client/CN=client.net"\
	-keyout "$CERTDIR"/client_key.pem \
	-out "$CERTDIR"/client_cert.pem

openssl pkcs12 -export \
	-out "$CERTDIR"/api.pfx \
	-password pass:tnexus \
	-inkey "$CERTDIR"/api_key.pem -in "$CERTDIR"/api_cert.pem

openssl pkcs12 -export \
	-out "$CERTDIR"/client.pfx \
	-password pass:tnexus \
	-inkey "$CERTDIR"/client_key.pem -in "$CERTDIR"/client_cert.pem
