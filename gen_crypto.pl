#! /usr/bin/perl

my $private_key = "./crypto/rsa_private.pem";
my $public_key = "./crypto/rsa_public.pem";
my $newreq = "./crypto/rsa_newreq.pem";
my $cert = "./crypto/rsa_cert.crt";

my $private_cmd = "openssl genrsa -out $private_key";
my $public_cmd = "openssl rsa -in $? -pubout -out $public_key";
my $newreq_cmd = 'openssl req -new -nodes -sha512 -out newreq.pem -config ./https.cnf -keyout newkey.pem -days 1826';
my $sign_cmd = 'openssl ca -config ./https.cnf -policy policy_match -md sha512 -out newcert.pem -infiles newreq.pem';
my $newcert_cmd = 'openssl req -new -x509 -nodes -sha512 -config ./https.cnf -keyout newkey.pem -out newcert.pem -days 1826';

print $newcert_cmd . "\n";
