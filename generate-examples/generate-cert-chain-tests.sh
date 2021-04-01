#!/bin/bash
# This script generates a 3-cert ECDSA chain (root -> CA -> issuer) valid for 10 years.
# Leaf cert uses P-256 (as per the SMART Health Card Framework), CA and root CA use the
# increasingly stronger P-384 and P-521, respectively (simulatate real PKI).

# directory where intermediate files are kept
tmpdir=testfiles
mkdir -p $tmpdir

# generate one P-256 3-chain
openssl req -x509 -new -newkey ec:<(openssl ecparam -name secp521r1) -keyout $tmpdir/root_CA_1.key -out $tmpdir/root_CA_1.crt -nodes -subj "/CN=SMART Health Card Example Root CA" -days 3650 -config openssl_ca.cnf -extensions v3_ca -sha512
openssl req -new -newkey ec:<(openssl ecparam -name secp384r1) -keyout $tmpdir/CA_1.key -out $tmpdir/CA_1.csr -nodes -subj "/CN=SMART Health Card Example CA" -config openssl_ca.cnf -extensions v3_ca -sha384
openssl x509 -req -in $tmpdir/CA_1.csr -out $tmpdir/CA_1.crt -CA $tmpdir/root_CA_1.crt -CAkey $tmpdir/root_CA_1.key -CAcreateserial -days 3650 -extfile openssl_ca.cnf -extensions v3_ca -sha512
openssl req -new -newkey ec:<(openssl ecparam -name prime256v1) -keyout $tmpdir/issuer_1.key -out $tmpdir/issuer_1.csr -nodes -subj "/CN=SMART Health Card Example Issuer" -config openssl_ca.cnf -extensions v3_issuer -sha256
openssl x509 -req -in $tmpdir/issuer_1.csr -out $tmpdir/issuer_1.crt -CA $tmpdir/CA_1.crt -CAkey $tmpdir/CA_1.key -CAcreateserial -days 3650 -extfile openssl_ca.cnf -extensions v3_issuer -sha384

# generate another P-256 3-chain
openssl req -x509 -new -newkey ec:<(openssl ecparam -name secp521r1) -keyout $tmpdir/root_CA_2.key -out $tmpdir/root_CA_2.crt -nodes -subj "/CN=SMART Health Card Example Root CA" -days 3650 -config openssl_ca.cnf -extensions v3_ca -sha512
openssl req -new -newkey ec:<(openssl ecparam -name secp384r1) -keyout $tmpdir/CA_2.key -out $tmpdir/CA_2.csr -nodes -subj "/CN=SMART Health Card Example CA" -config openssl_ca.cnf -extensions v3_ca -sha384
openssl x509 -req -in $tmpdir/CA_2.csr -out $tmpdir/CA_2.crt -CA $tmpdir/root_CA_2.crt -CAkey $tmpdir/root_CA_2.key -CAcreateserial -days 3650 -extfile openssl_ca.cnf -extensions v3_ca -sha512
openssl req -new -newkey ec:<(openssl ecparam -name prime256v1) -keyout $tmpdir/issuer_2.key -out $tmpdir/issuer_2.csr -nodes -subj "/CN=SMART Health Card Example Issuer" -config openssl_ca.cnf -extensions v3_issuer -sha256
openssl x509 -req -in $tmpdir/issuer_2.csr -out $tmpdir/issuer_2.crt -CA $tmpdir/CA_2.crt -CAkey $tmpdir/CA_2.key -CAcreateserial -days 3650 -extfile openssl_ca.cnf -extensions v3_issuer -sha384

# valid P-256 2-chain
openssl req -new -newkey ec:<(openssl ecparam -name prime256v1) -keyout $tmpdir/issuer_2chain.key -out $tmpdir/issuer_2chain.csr -nodes -subj "/CN=SMART Health Card Example Issuer" -config openssl_ca.cnf -extensions v3_issuer -sha256
openssl x509 -req -in $tmpdir/issuer_2chain.csr -out $tmpdir/issuer_2chain.crt -CA $tmpdir/root_CA_1.crt -CAkey $tmpdir/root_CA_1.key -CAcreateserial -days 3650 -extfile openssl_ca.cnf -extensions v3_issuer -sha512
node src/certs-to-x5c.js --key $tmpdir/issuer_2chain.key --cert $tmpdir/issuer_2chain.crt --cert $tmpdir/root_CA_1.crt --private $tmpdir/valid_2_chain.private.json --public $tmpdir/valid_2_chain.public.json

# valid P-256 self-signed
openssl req -x509 -new -newkey ec:<(openssl ecparam -name prime256v1) -keyout $tmpdir/self.key -out $tmpdir/self.crt -nodes -subj "/CN=SMART Health Card Example Root CA" -days 3650 -config openssl_ca.cnf -extensions v3_issuer -sha256
node src/certs-to-x5c.js --key $tmpdir/self.key --cert $tmpdir/self.crt --private $tmpdir/valid_1_chain.private.json --public $tmpdir/valid_1_chain.public.json

# create invalid chain
node src/certs-to-x5c.js --key $tmpdir/issuer_1.key --cert $tmpdir/issuer_1.crt --cert $tmpdir/CA_2.crt --cert $tmpdir/root_CA_2.crt --private $tmpdir/invalid_chain.private.json --public $tmpdir/invalid_chain.public.json

# create cert mismatch
node src/certs-to-x5c.js --key $tmpdir/issuer_1.key --cert $tmpdir/issuer_2.crt --cert $tmpdir/CA_2.crt --cert $tmpdir/root_CA_2.crt --private $tmpdir/cert_mismatch.private.json --public $tmpdir/cert_mismatch.public.json

# generate a P-256 cert without Subject Alt Name extension
openssl req -new -newkey ec:<(openssl ecparam -name prime256v1) -keyout $tmpdir/issuer_sans_SAN.key -out $tmpdir/issuer_sans_SAN.csr -nodes -subj "/CN=SMART Health Card Example Issuer" -config openssl_ca_tests.cnf -extensions v3_issuer_no_SAN -sha256
openssl x509 -req -in $tmpdir/issuer_sans_SAN.csr -out $tmpdir/issuer_sans_SAN.crt -CA $tmpdir/root_CA_1.crt -CAkey $tmpdir/root_CA_1.key -CAcreateserial -days 3650 -extfile openssl_ca_tests.cnf -extensions v3_issuer_no_SAN -sha512
node src/certs-to-x5c.js --key $tmpdir/issuer_sans_SAN.key --cert $tmpdir/issuer_sans_SAN.crt --cert $tmpdir/root_CA_1.crt --private $tmpdir/invalid_no_SAN.private.json --public $tmpdir/invalid_no_SAN.public.json

# generate a P-256 cert with DNS Subject Alt Name extension
openssl req -new -newkey ec:<(openssl ecparam -name prime256v1) -keyout $tmpdir/issuer_DNS_SAN.key -out $tmpdir/issuer_DNS_SAN.csr -nodes -subj "/CN=SMART Health Card Example Issuer" -config openssl_ca_tests.cnf -extensions v3_issuer_dns -sha256
openssl x509 -req -in $tmpdir/issuer_DNS_SAN.csr -out $tmpdir/issuer_DNS_SAN.crt -CA $tmpdir/root_CA_1.crt -CAkey $tmpdir/root_CA_1.key -CAcreateserial -days 3650 -extfile openssl_ca_tests.cnf -extensions v3_issuer_dns -sha512
node src/certs-to-x5c.js --key $tmpdir/issuer_DNS_SAN.key --cert $tmpdir/issuer_DNS_SAN.crt --cert $tmpdir/root_CA_1.crt --private $tmpdir/invalid_DNS_SAN.private.json --public $tmpdir/invalid_DNS_SAN.public.json

# TODO: expired cert, not-yet-valid cert
