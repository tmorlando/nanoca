# CA tool

This is not a ready product but more like a gist showing how to do certain things.

## Purpose

- Provides user interface for
  - CA keypair generation and self-issuance, 
  - issuing certificates based on  sigining requests,
  - listing various object, and
  - revocation/CRL generation.

- Keeps track on issues and revoked certificates.
- Implements secret sharing for CA key access using SSSS (Shamir Secret Sharing Scheme) if available

- Requires OpenSSL 3.x and naturally Python 3.7+

## Examples

### Setup

Packaging
~~~
$ make # aka python3 -m build
~~~

Installing
~~~
$ pip install nanoCA-1.0.0-py3-none-any.whl
$ alias CA="python -m nanoCA"
~~~

### Setup

this is done once; second time will fail without altering system state
~~~
$ CA init
~~~

## Create Top Level CA

This creates the top level CA (selfsigned) with default RSA:8k key. For the key we enable 2 / 20 secret sharing. The key generator makes the key and CSR that can be certified with `issue` command.

After Issuing the CA certificate we'll create a CRL that can be published.

~~~
$ CA keygen --shares 2 20 root-ca
$ CA issue \
   --subject /DC=IKI/DC=FI/DC=TMO/CN=root-ca \
   --altname DNS=root-ca.tmo.iki.fi --altname EMAIL=root@root-ca.tmo.iki.fi \
   --usage TOP --name root-ca \
   root-ca /tmp/test/certificates/root-ca.csr /tmp/root-ca.crt
$ CA crl
   --shares 2 --validity 182
   root-ca /tmp/crl-top-without-revoked-certs.crl
~~~

## Create Intermediate (Sub) CA

Create a key pair for the sub-CA. This key is passphrase protected - the user will be prompted for the password instead of shares.
This also demonstrates mixed key type hierarchy.

As the Root CA uses secret sharing, we'll need to provide number of secrets it uses (XXX: we should store this by side of the key instead)

~~~
$ CA keygen --keytype ED448 --name sub-ca
$ CA issue
   --shares 2
   --subject /DC=IKI/DC=FI/DC=TMO/CN=sub-ca \
   --altname DNS=sub-ca.tmo.iki.fi --altname EMAIL=root@sub-ca.tmo.iki.fi \
   --usage INTERMEDIATE --name sub-ca
   root-ca /tmp/test/certificates/sub-ca.csr /tmp/sub-ca.crt
$ CA crl
   --validity 91
   sub-ca /tmp/crl-sub-without-revoked-certs.crl
~~~

## Create a LEAF certificate

First create key pair and CSR on some device, then transmit the req.pem to the CA.  The CA check that request is from legit source, creates a certificate and registers issuance. The resulting certifiate leaf.crt can then be sent to the requestor.

~~~
$ openssl req -new -subj '/CN=Node 1/' -noenc -out leaf.pem

$ CA issue
   --subject '/DC=IKI/DC=FI/DC=TMO/CN=Leaf Device One' \
   --altname DNS=leaf1.devices.tmo.iki.fi --altname EMAIL=support@devices.tmo.iki.fi --altname IP=1.2.3.4
   sub-ca
   /tmp/leaf.pem /tmp/leaf.crt
~~~

Subject Alternative Names can be of types
* DNS; DNS names for hosts
* IP; IP address for hosts
* EMAIL; E-mail address for user
* UPN; creates Microsoft OID'ed OtherName SAN for User Principal Names

## Revoke certificate

Revoke leaf certificate issued above. This can be done either using the CA stored certificate, or by serial number.

~~~
$ CA list --type cert 'Leaf Device One'
Status Serial     Path                                      Subject
V      123123     afcc77c8-2d2b-4957-8306-0c0ae571ff13.crt   /DC=IKI/DC=FI/DC=TMO/CN=Leaf Device One/

$ CA revoke sub-ca $certsdir/afcc77c8-2d2b-4957-8306-0c0ae571ff13.crt

or

$ CA revoke --serial 123123 sub-ca
$ CA crl sub-ca /tmp/crl-sub-with-revoked-certs.crl
~~~
