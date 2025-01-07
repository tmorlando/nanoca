import base64
import click
import getpass
import ipaddress
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid

from typing import List, Sequence, Tuple

openssl = "openssl"
issuercnf = "/usr/local/openssl-3.3/ssl/openssl.cnf"
version = "1.0.0"

provider_args = [] if os.getenv("NO_FIPS") else ["--provider", "fips"]

basepath = os.path.expanduser("~/.nanoca")
certs = "{basepath}/certificates"  # Issued certs and reqs by CA
crls = "{basepath}/crls"  # Revocation reasons and CRLs
keys = "{basepath}/keys"  # CA keys and certs

min_pass_len = 3  # XXX:tmo


def make_env(d):
    e = os.environ
    e.update(d)
    e.update({"OPENSSL_CONF": os.getenv("OPENSSL_CONF", issuercnf)})
    return e


##############################################################################
# Secret Sharing part
#
def shares_usage(keyname, shares, threshold, count):
    print("Toimintaohjeet avainten käsittelyyn...")
    print("Avainjaot:")
    print("\n".join(share.decode('utf-8') for share in shares))
    with open(f"{keyname}.txt", "w") as o:
        # Save some useful hints (like original threshold) by the key
        o.write(f"private key {keyname}.prv is protected using secret sharing scheme with threshold value of {threshold}.\n")
        o.write(f"To use the key, you'll need to provide --shares={threshold} argument for the issue, and revoke commands\n")
    with open(f"{keyname}.inf", "w") as o:
        o.write(f"{threshold}\n")


def share2user(share: bytes) -> bytes:
    prefix, data = share.split(b'-')
    return prefix + b'-' + base64.b64encode(base64.b16decode(data, casefold=True))


def user2share(share: bytes) -> bytes:
    prefix, data = share.split(b'-')
    return prefix + b'-' + base64.b16encode(base64.b64decode(data)).lower()


assert user2share(share2user(b'01-b4164581')) == b'01-b4164581', "share-reader broken"


def shares_generate(threshold: int, count: int) -> Tuple[bytes, List[bytes]]:
    provider_args_str = " ".join(provider_args)
    secretgen_cmd = f"{openssl} rand {provider_args_str} -base64 18"
    kekgen = subprocess.Popen(secretgen_cmd.split(), stdout=subprocess.PIPE)
    secret = kekgen.communicate()[0].strip()
    assert kekgen.wait() == 0 and secret and len(secret) == 24, "KeyGen: getting KEK failed"

    sharesgen_cmd = f"ssss-split -q -t {threshold} -n {count}"
    sharegen = subprocess.Popen(sharesgen_cmd.split(),
                                stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    secret_shares = [share2user(share)
                     for share in sharegen.communicate(secret)[0].split(b'\n') if share]
    assert sharegen.wait() == 0 and len(secret_shares) == count, "KeyGen: secret-sharing failed"

    return secret, secret_shares


def shares_combine(threshold: int) -> bytes:
    shares = []
    i = 0
    while True:
        while i < threshold:
            try:
                shard = getpass.getpass(f"Enter share #{i}: ").encode('utf-8')
                shares.append(user2share(shard))
                i += 1
            except Exception as e:
                print(f"Share #{i} decode failed: ", str(e))
                continue

        sharesgen_cmd = f"ssss-combine -q -t {threshold}"
        sharegen = subprocess.Popen(sharesgen_cmd.split(),
                                    stdout=subprocess.PIPE,
                                    stdin=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
        try:
            _, secret = sharegen.communicate(b"\n".join(shares) + b'\n')
            secret = secret.strip()
            assert sharegen.wait() == 0 and len(secret) == 24
            _ = base64.decodebytes(secret)  # we know it is really base64
            break
        except Exception:
            print("Combining shares failed: Try again")
            continue
    return secret


##############################################################################
# Index file is a Tab separated file.
#
# OpenSSL index.txt file format
#
# 0 status flag (V=valid, R=revoked, E=expired).
# 1 expiration date in YYMMDDHHMMSSZ format.
# 2 revocation date in YYMMDDHHMMSSZ[,reason] format. Empty if not revoked.
# 3 serial number in hex.
# 4 filename or literal string ‘unknown’.
# 5 distinguished name.
#

def index_issue(ctx, caname,
                hex_serial, subject, expires, certfile='unknown') -> None:
    old_idx_name = idx_name(ctx, caname)
    revoked = ""
    subject = subject.replace(", ", "/")
    with open(old_idx_name, "r") as old_index:
        _, new_idx_name = tempfile.mkstemp(prefix=old_idx_name + ".", text=True)
        with open(new_idx_name, "w") as new_index:
            while True:
                line = old_index.readline()
                if not line:
                    break
                new_index.write(line)
            new_index.write(f"V\t{expires}\t{revoked}\t{hex_serial}\t{certfile}\t/{subject}\n")

        # done; now atomic update with backups
        for gen in range(0, 10):
            bd = old_idx_name + f".backup-{10-gen}"
            bs = old_idx_name + f".backup-{10-(gen+1)}"
            if os.path.exists(bs):
                os.rename(bs, bd)
        os.rename(old_idx_name, old_idx_name + ".backup-0")
        os.rename(new_idx_name, old_idx_name)


def index_find(ctx, caname: str, pattern: str) -> List[str]:
    index_file = idx_name(ctx, caname)
    result = []
    with open(index_file, "r") as index:
        for line in index.readlines():
            r = line.strip().split('\t')
            if not re.match(pattern or r".*", r[5]):
                continue
            result.append(r)
    return result


def index_revoke(ctx, caname, hex_serial, reason) -> bool:
    revoked_at = time.strftime("%y%m%d%H%M%SZ", time.gmtime())
    old_idx_file = idx_name(ctx, caname)
    import pdb
    pdb.set_trace()
    with open(old_idx_file, "r") as old_index:
        found = False
        lineno = 0
        _, new_idx_file = tempfile.mkstemp(prefix=old_idx_file + ".", text=True)
        with open(new_idx_file, "w") as new_index:
            while True:
                line = old_index.readline()
                if not line:
                    break

                lineno += 1
                parts = line.strip().split('\t')
                if not parts:
                    continue  # eats empty lines

                if len(parts) != 6:
                    logging.warning("TSV index file: %s:%s corrupt (no 6 columns): %s",
                                    old_idx_file, lineno, line)
                    continue

                if parts[0] == 'R':
                    if hex_serial == parts[3]:
                        found = True
                        logging.warning("Certificate serial %s already revoked on %s",
                                        hex_serial, parts[2])
                elif parts[0] in ('V', 'E'):
                    if hex_serial == parts[3]:
                        logging.info("Revoking serial %s", hex_serial)
                        found = True
                        new_parts = ['R', parts[1], revoked_at + "," + reason]
                        new_parts.extend(parts[3:])
                        parts = new_parts
                else:
                    if not parts[0].startswith('#'):
                        logging.warning("Skipping gibberish: %s", " ".join(parts))
                        continue  # gibberish, skipped

                new_index.write("\t".join(parts))
                new_index.write("\n")

        if not found:
            logging.warning("Certificate missing from index not revoked: %s", hex_serial)
            os.remove(new_idx_file)
            return False

        # done; now atomic update with backups
        for gen in range(0, 9):
            bd = old_idx_file + f".backup-{10-gen}"
            bs = old_idx_file + f".backup-{10-(gen+1)}"
            if os.path.exists(bs):
                os.rename(bs, bd)
        os.rename(old_idx_file, old_idx_file + ".backup-0")
        os.rename(new_idx_file, old_idx_file)
        return True


##############################################################################
class Global:
    def __init__(self):
        self.verbose = 0
        self.dry_run = False
        self.basepath = basepath


@click.group()
@click.pass_context
def toplevel(ctx, *, basepath, verbose, version, dry_run):
    if version:
        print("Certificate Hierarchy Tool")
        print("Version: ", version)
        os.exit(0)
    ctx.obj = Global(basepath, verbose, dry_run)


@toplevel.command(name="init")
@click.pass_obj
def cmd_init(obj):
    try:
        os.makedirs(certs.format(basepath=obj.basepath), mode=0o750, exist_ok=False)
        os.makedirs(crls.format(basepath=obj.basepath), mode=0o750, exist_ok=False)
        os.makedirs(keys.format(basepath=obj.basepath), mode=0o700, exist_ok=False)
        logging.info("Initialized CA to: %r", str(obj.basepath))
    except OSError:
        logging.error("Already initialized to: %r", str(obj.basepath))


##############################################################################
@click.group()
def list():
    click.echo("list")


@list.command(name="list")
@click.pass_obj
def cmd_list(obj):
    for index_name in [f for f in os.listdir(obj.basepath + '/' + 'certificates')]:
        if not index_name.endswith("-index.txt"):
            continue
        print(index_name.replace('-index.txt', ''))


##############################################################################
@click.group()
def show():
    """Show certificates related to ISSUER.

    Optionally a regex PATTERN can be used to filter by subject-name.
    """
    click.echo("show")


#@click.option("--details/--no-details", default=False, help="show more details from certificate")
@show.command(name="show")
@click.argument("issuer", type=str)
@click.argument("pattern", type=str, required=False)
@click.pass_obj
def cmd_show(obj, *, issuer, pattern):
    print("Stat  Serial                                   Stamp         : Subject")
    for status, expires, revoked, serial, path, name in index_find(obj, issuer, pattern):
        if status != 'R':
            print(f"{status:2s}    {serial:20s} {expires} : {name}")
        else:
            print(f"{status:2s}    {serial:20s} {revoked} : {name}")


##############################################################################
@click.group()
def keygen():
    click.echo("keygen")


def key_name(ctx, base):
    return keys.format(basepath=ctx.basepath) + "/" + base + ".prv"


def req_name(ctx, base):
    return certs.format(basepath=ctx.basepath) + "/" + base + ".csr"


def crt_name(ctx, base):
    return certs.format(basepath=ctx.basepath) + "/" + base + ".crt"


def idx_name(ctx, base):
    return certs.format(basepath=ctx.basepath) + "/" + base + "-index.txt"


def crl_name(ctx, base):
    return crls.format(basepath=ctx.basepath) + "/" + base + ".crl"


def store_file(src_path, dst_path):
    with open(src_path, "rb") as s:
        with open(dst_path, "wb") as d:
            d.write(s.read())


# generate encrypted Asymmetric KEY PAIR

# The new key pair of given type and size (default RSA:8192 bits) is written
# into given output file prefix. The private key is stored as prefix.PRV and
# the public portion is prefix.PUB, and an empty PKCS#10 certificate request
# into prefix.REQ
#
# The RSA Key Encryption Key (KEK) is prompted from the user.
#
# If shares option is given (--shares required total) the KEK is random, and
# split into `total` shares out of these `required` are needed in order to
# decrypt the key.
@keygen.command(name="keygen")
@click.option('--keytype',
              type=click.Choice(['RSA', 'RSA-PSS', 'P-521', 'P-384', 'ED25519', 'ED448'], case_sensitive=False),
              default='RSA')
@click.option('--size',
              type=click.Choice(['3072', '4096', '6144', '8192']),
              default='8192')
@click.option('--shares', nargs=2, type=int)
@click.option('--keyfile', nargs=1, type=str)
@click.option('--reqfile', nargs=1, type=str)
@click.argument('name', type=str)  # this becomes name of private key on store
@click.pass_obj
def cmd_keygen(obj, *, keytype, size, shares, keyfile, reqfile, name):
    secret = b""
    secret_shares = []
    threshold = count = 0
    if shares:
        threshold, count = shares
        secret, secret_shares = shares_generate(threshold, count)
    else:
        while not secret:
            secret1 = getpass.getpass("Enter passphrase for private key: ")
            if len(secret1) < min_pass_len:
                print(f"passphrase is too short; {min_pass_len} or more character minimum")
                continue
            secret2 = getpass.getpass("Confirm passphrase: ")
            if secret1 != secret2:
                print("passphrases do not match")
                continue
            secret = secret1.encode('utf-8')

    assert isinstance(secret, bytes)

    flag_pkeyopt = ""
    pkeyopts = ""
    if keytype.startswith('P-'):
        flag_pkeyopt = "-pkeyopt"
        pkeyopts += f"ec_paramgen_curve:{keytype}"
        keytype = "EC"
    if keytype.startswith('RSA'):
        flag_pkeyopt = "-pkeyopt"
        pkeyopts += f"rsa_keygen_bits:{size}"

    keygen_cmd = [
        openssl,
        "genpkey", "-quiet", "-algorithm", keytype]
    keygen_cmd += provider_args

    if flag_pkeyopt:
        keygen_cmd.extend([flag_pkeyopt, pkeyopts])

    keyname = key_name(obj, name)
    keygen_cmd.extend([
        "-out", keyname, "-outform", "PEM", "-aes256", "-pass", "env:KEYPASS"])

    if not obj.dry_run:
        keygen = subprocess.Popen(keygen_cmd,
                                  stdout=subprocess.PIPE, stdin=subprocess.PIPE,
                                  env=make_env({"KEYPASS": secret.decode('utf-8')}))
        assert keygen.wait() == 0, "KeyGen: key generation failed"
        if keyfile:
            store_file(keyname, keyfile)
    else:
        print(" ".join(keygen_cmd))

    # Then construct the request (reuses the key with secret checking things still work)
    request_cmd = [
        openssl,
        "req",
        "-new", "-subj", "/DC=nonexistent/DC=tld/CN=EmptyCSR/",
        "-key", key_name(obj, name), "-inform", "PEM",  "-passin", "env:KEYPASS",
        "-out", req_name(obj, name), "-outform", "PEM"
    ]
    request_cmd += provider_args

    if not obj.dry_run:
        req = subprocess.Popen(request_cmd,
                               stdout=subprocess.PIPE, stdin=subprocess.PIPE,
                               env=make_env({"KEYPASS": secret.decode('utf-8')}))
        assert req.wait() == 0, "KeyGen: key generation failed"
        if reqfile:
            store_file(req_name(obj, name), reqfile)
    else:
        print(" ".join(request_cmd))

    if shares:
        shares_usage(key_name(obj, name), secret_shares, threshold, count)


##############################################################################

def extract_altnames(names: Sequence[str]) -> List[str]:
    # name= {IP,DNS,EMAIL:UPN}:{VALUE}
    names_by_type = dict()
    altnames = []
    for name in names or []:
        try:
            t, v = name.split('=', maxsplit=1)
            t = t.upper()
            if t not in ('IP', 'DNS', 'EMAIL', 'UPN'):
                raise ValueError
            if t == 'EMAIL':
                if '@' not in v:
                    raise ValueError(f"{t} must contain '@'-sign")
                t = 'email'
            if t == 'UPN':
                if '@' not in v:
                    raise ValueError(f"{t} must contain '@'-sign")
                t = 'otherName'
                v = f"1.3.6.1.4.1.311.20.2.3;UTF8:{v}"
            if t == 'DNS' and '.' not in v:
                raise ValueError(f"{t} must contain '.'-sign")
            if t == 'IP':
                try:
                    ipaddress.ip_address(v)
                except ValueError:
                    raise ValueError("IP address does not parse")

            names_of_type = names_by_type.get(t, [])
            altnames.append(f"{t}.{1 + len(names_of_type)} = {v}")
            names_of_type.append(v)
            names_by_type[t] = names_of_type

        except ValueError as e:
            print("Names must be of format: <type>:<value>, where")
            print(" type is one-of(DNS,IP,EMAIL,UPN) and value presentation depends on type")
            print(" error: ", str(e))

    return altnames


@click.group()
def issue():
    click.echo("issue")


@issue.command(name="issue")
@click.option('--shares',
              help="Number of key shares require to use issuer's private key.",
              type=int, default=0)  # issuer is protected using secret sharing with this threshold
@click.option('--subject',
              help="Subject name for the issued certificate. /DC=IKI/DC=FI/CN=TMO",
              type=str)
@click.option('--altname',
              help="Subject altName {DNS,IP,EMAIL,UPN}=value.",
              type=str, multiple=True)
@click.option('--usage',
              help="Location of cert on the hierarchy - top, sub, or SIG/KEM for leaf",
              type=click.Choice(['TOP', 'SUB', 'SIG', 'KEM'], case_sensitive=False),
              default='SIG')
@click.option("--name",
              help="Mandatory Friendly name for the CA certificate issued. Only used for CA's with local keys.",
              nargs=1, type=str)
@click.argument('issuer', type=str, required=True)  # also name of key and cert (when issuing top, cert written here)
@click.argument('reqfile', type=click.Path(exists=True), required=True)
@click.argument('certfile', type=click.Path(exists=False))
@click.pass_obj
def cmd_issue(obj: Global, *,
              shares: int, subject: str, altname: Sequence[str],
              usage: str,
              name: str,
              issuer: str, reqfile: str, certfile: str) -> None:

    # Subject format /DC=COM/DC=SSH/DC=CTO/CN=Root CA/ or such
    issue_cmd = [openssl, "x509", "-req"]
    issue_cmd += provider_args

    usage = usage.upper()
    if not os.path.exists(key_name(obj, issuer)):
        logging.error(f"Requested issuer {issuer} does not have keypair")
        exit(1)

    if usage == 'TOP':  # making top level selfsigned
        validity = str(20 * 365)
        certname = issuer
        issue_cmd.extend([
            "-key", key_name(obj, issuer),
            "-rand_serial",
            "-extensions", "certext_ca", "-days", validity
        ])
        # touch the index for CA
        with open(idx_name(obj, issuer), "a") as f:
            f.write("")
    elif usage == 'SUB':
        if not os.path.exists(crt_name(obj, issuer)):
            logging.error("Toplevel CA certificate for name %s not found file %s",
                          issuer, crt_name(obj, issuer))
            sys.exit(1)

        certname = name or str(uuid.uuid4())

        validity = str(10 * 365)
        issue_cmd.extend([
            "-CA", crt_name(obj, issuer),
            "-CAkey", key_name(obj, issuer),
            "-rand_serial",
            "-extensions", "certext_ca", "-days", validity
        ])
        # touch the index for CA
        if name:
            with open(idx_name(obj, name), "a") as f:
                f.write("")
    else:
        assert usage in ('SIG', 'KEM')
        assert name is None

        certname = name or str(uuid.uuid4())
        validity = str(2 * 365 + 30)
        issue_cmd.extend([
            "-CA", crt_name(obj, issuer),
            "-CAkey", key_name(obj, issuer),
            "-rand_serial",
            "-extensions", "certext", "-days", validity
        ])

    altnames = extract_altnames(altname)

    if shares > 0:
        secret = shares_combine(shares)
    else:
        secret = getpass.getpass("Enter passphrase for private key: ").encode('utf-8')

    assert isinstance(secret, bytes)

    with tempfile.TemporaryDirectory(dir="/tmp/", prefix="nanoca") as dirpath:
        extpath = f"{dirpath}/extensions.cnf"
        issue_cmd.extend([
            "-extfile", extpath,
            "-sha512",
            "-passin", "env:KEYPASS",
            "-in", reqfile,
            "-out", crt_name(obj, certname),
        ])

        if subject:
            issue_cmd.extend(["-subj", subject])

        extlines = []
        if usage == 'TOP' or usage == 'SUB':
            extlines.append("[ certext_ca ]")
            extlines.append("keyUsage = cRLSign, keyCertSign")
            extlines.append("subjectKeyIdentifier=hash")
            extlines.append("authorityKeyIdentifier=keyid:always,issuer")
            extlines.append("subjectAltName = @altnames")
            # specialization; depth of hierarchy is two (ca, sub, sig/kem)
            if usage == 'TOP':
                extlines.append("basicConstraints = critical,CA:true,pathlen:1")
            else:
                extlines.append("basicConstraints = critical,CA:true,pathlen:0")
        else:
            extlines.append("[ certext ]")
            if usage == 'SIG':
                extlines.append("keyUsage = digitalSignature, nonRepudiation")
                extlines.append("extendedKeyUsage = serverAuth")
            if usage == 'KEM':
                extlines.append("keyUsage = keyEncipherment,keyAgreement")
            extlines.append("authorityKeyIdentifier = keyid:always")
            extlines.append("subjectAltName = @altnames")

        extlines.append("[ altnames ]")
        extlines.append("\n".join(altnames))

        with open(extpath, "w") as extfile:
            extfile.write("\n".join(extlines))
            extfile.write("\n")

        if not obj.dry_run:
            issue = subprocess.Popen(issue_cmd,
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     env=make_env({"KEYPASS": secret.decode('utf-8')}))
            assert issue.wait() == 0, f"Issue: certificate issue failed: {issue.stderr.read()}"

            _, subject, serial, expires = extract_issuer_subject_serial(crt_name(obj, certname))
            index_issue(obj, issuer, serial, subject, expires, certfile=crt_name(obj, certname))
            if certfile:
                store_file(crt_name(obj, certname), certfile)
        else:
            print(" ".join(issue_cmd))
            print("extension:")
            print("\n".join(extlines))


#############################################################################
#
# Revocation uses facilities from openssl-ca, as that's the only means for
# constructing CRLs... This involves construcing the index files.
#
@click.group()
def revoke():
    click.echo("revoke")


def extract_issuer_subject_serial(certpath: str):

    extract_cmd = [openssl, "x509", "-in", certpath, "-issuer", "-serial", "-subject", "-dates", "-noout"]
    extract = subprocess.Popen(extract_cmd, stdout=subprocess.PIPE)
    output, _ = extract.communicate()

    issuer = subject = serial = expires = ""
    for line in output.split(b'\n'):
        line = line.decode('utf-8')
        if line.startswith("subject="):
            subject = line.strip().replace("subject=", "")
        if line.startswith("serial="):
            serial = line.strip().replace("serial=", "").upper()
        if line.startswith("issuer="):
            issuer = line.strip().replace("issuer=", "")
        if line.startswith("notAfter="):
            s = line.strip().replace("notAfter=", "")
            expires = time.strftime("%y%m%d%H%M%SZ",
                                    time.strptime(s, "%b %d %H:%M:%S %Y %Z"))

    return issuer, subject, serial, expires


def do_revocation(ctx: Global,
                  caname: str, hex_serial: str, reason: str) -> None:
    if index_revoke(ctx, caname, hex_serial, reason):
        logging.info("%s revoked: issuer: %r serial: %r cause: %r",
                     str(caname), str(hex_serial), str(reason))


def do_build_crl(ctx: Global, caname: str, crlname: str, *,
                 shares: int = 0, validity: int = 1) -> None:
    revoke_cmd = [
        openssl,
        "ca",
        "-md", "sha512",
        "-gencrl", "-crldays", str(validity), "-out", crlname,
        "-name", caname,
        "-cert", crt_name(ctx, caname),
        "-keyfile", key_name(ctx, caname),
        "-passin", "env:KEYPASS",
    ]
    revoke_cmd += provider_args

    if shares > 0:
        secret = shares_combine(shares)
    else:
        secret = getpass.getpass("Enter passphrase for private key: ").encode('utf-8')

    assert isinstance(secret, bytes)

    with tempfile.TemporaryDirectory(dir="/tmp/", prefix="nanoca") as dirpath:
        crlpath = f"{dirpath}/gencrl.cnf"
        crllines = [
            f"[ {caname} ]",
            f"database = {idx_name(ctx, caname)}"
        ]
        with open(crlpath, "w") as crlfile:
            crlfile.write("\n".join(crllines))

        revoke_cmd.extend(["-config", crlpath])

        if not ctx.dry_run:
            revoke = subprocess.Popen(revoke_cmd,
                                      stdout=subprocess.PIPE, stdin=subprocess.PIPE,
                                      env=make_env({"KEYPASS": secret.decode('utf-8')}))
            assert revoke.wait() == 0, "Issue: certificate issue failed"
        else:
            print(" ".join(revoke_cmd))


# Workflow
#  $ ca revoke --reason keycompromise issuername revoked-cert-path
#  $ ca crl --validity 10 issuer-cert-path
@revoke.command(name="revoke")
@click.option('--reason',
              type=click.Choice(['unspecified',
                                 'keyCompromise',
                                 'CACompromise',
                                 'affiliationChanged',
                                 'superseded',
                                 'cessationOfOperation',
                                 'certificateHold'],  # <-strict format
                                case_sensitive=False),
              default='unspecified')
@click.option('--serial', type=str)
@click.argument('issuer', type=str, required=True)
@click.argument('certificate', type=click.Path(exists=True), required=False)
@click.pass_obj
def cmd_revoke(obj, *,
               issuer: str, serial: str, certificate: str, reason: str):

    _, caname, _, _ = extract_issuer_subject_serial(crt_name(obj, issuer))
    if certificate:
        issuername, _, serial, _ = extract_issuer_subject_serial(certificate)
        assert issuername == caname, "Can't revoke other's certificates"
    elif serial:
        issuername = caname
    else:
        print("Either certificate path, or serial need to be given")
        sys.exit(1)
    do_revocation(obj, issuer, serial, reason)


@revoke.command(name="crl")
@click.argument('issuer', type=str, required=True)
@click.argument('crlfile', type=click.Path(exists=False), required=True)
@click.option('--validity', type=int, default=1)
@click.option('--shares', type=int, default=0)
@click.pass_obj
def cmd_crl_refresh(obj: Global, *,
                    issuer: str, crlfile: str, validity: int, shares: int):
    """Build CRL for the given issuer certificate."""
    issuername, _, serial, _ = extract_issuer_subject_serial(crt_name(obj, issuer))
    do_build_crl(obj, issuer, crlfile, shares=shares, validity=validity)


##############################################################################
# global options; the Global context storing these is given as
# obj-argument for the cmd_*() functions.
#
def pcb(arg):
    def setter(ctx, obj, value):
        if not getattr(ctx, 'obj'):
            ctx.obj = Global()
        setattr(ctx.obj, arg, value)
    return setter


def version_cb(ctx, obj, value):
    if value:
        click.echo(version)
        sys.exit(0)


main = click.CommandCollection(
    sources=[toplevel, keygen, issue, list, show, revoke],
    params=[click.Option(['--basepath', '-B'],
                         callback=pcb('basepath'), default=basepath, type=click.Path()),
            click.Option(['--verbose', '-v'],
                         callback=pcb('verbose'), count=True),
            click.Option(['--dry-run', '-n'],
                         callback=pcb('dry_run'), is_flag=True, default=False),
            click.Option(['--version', '-V'],
                         callback=version_cb, is_flag=True, default=False)])


if __name__ == '__main__':
    main()
