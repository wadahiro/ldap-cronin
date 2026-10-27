# -*- coding: utf-8 -*-
# Samba4 only: a helper that receives operations as JSON lines from the host side (ldap-cronin) and operates directly on sam.ldb.
#
# Over LDAP, objects cannot be created with a specified objectGUID / objectSid (replmd_add rejects it).
# Using Samba internals (system privileges + the provision and relax controls) allows creating them with the given values. This is not a supported usage and
# depends on the Samba version, so at startup it actually tries the same operation (and rolls it back) and fails on the spot if it does not work.
#
# Protocol: one request (JSON) per line on standard input, one response (JSON) per line on standard output.
# All values are base64. Output from libraries is redirected to standard error so that standard output carries only the protocol.
import base64
import json
import os
import subprocess
import sys
import time
import traceback
import uuid

# Duplicate the protocol's stdout, then redirect later print and library output to stderr.
proto = os.fdopen(os.dup(1), "w", buffering=1)
sys.stdout = sys.stderr

import ldb  # noqa: E402
import samba  # noqa: E402
from samba import dsdb  # noqa: E402
from samba.auth import admin_session, system_session  # noqa: E402
from samba.dcerpc import misc, security  # noqa: E402
from samba.ndr import ndr_pack, ndr_unpack  # noqa: E402
from samba.param import LoadParm  # noqa: E402
from samba.samdb import SamDB  # noqa: E402

TESTED_SAMBA_PREFIX = "4.19."  # version verified by measurement; warn on any other (the self-check actually tries the operation on the spot)
CONTROLS = ["provision:0", "relax:0"]  # controls needed to create with a specified objectGUID / objectSid

lp = LoadParm()
lp.load("/etc/samba/smb.conf")
db = SamDB(url="/var/lib/samba/private/sam.ldb", session_info=system_session(), lp=lp)
BASE = str(db.get_default_basedn())
DOMAIN_SID = str(db.get_domain_sid())
max_rid = 0  # largest RID among the imported objectSids; at exit the lab's RID allocation is advanced past it

# fast_password: the first user given a password gets it through setpassword, which derives every hash (NT, the
# Kerberos keys, supplementalCredentials); the NT hash it got (unsalted, so the same for every user with that
# password) is then written to the others directly with the bypass control, which derives nothing else. Most of the
# time of a user is the Kerberos keys (salted with the account name, so they cannot be shared).
FAST = False
nt_hashes = {}  # password -> NT hash
fast_count = 0

# The attributes the server keeps for an object, the source's on the lab ([target.lab] server_attributes): an add
# takes the time of the add as whenCreated whatever it is given, even with the provision and relax controls, and
# the others are the server's own; a modify as the system session then sets each (over LDAP only the system may;
# Windows refuses them all). Measured on 4.19.5: kept across a restart, dbcheck clean. Not settable that way:
# whenChanged (every change gives it the time again), pwdLastSet (0 or -1 only), the USNs (each DC's counters).
SERVER_ATTRS = ["whenCreated", "lastLogonTimestamp", "lastLogon", "logonCount", "lockoutTime", "badPwdCount",
                "sIDHistory", "mS-DS-CreatorSID"]
SERVER = False
server_count = 0
SERVER_LOWER = {n.lower() for n in SERVER_ATTRS}


def set_server_attrs(dn, attrs):
    m = ldb.Message(ldb.Dn(db, dn))
    for name, values in attrs.items():
        m[name] = ldb.MessageElement(values, ldb.FLAG_MOD_REPLACE, name)
    db.modify(m)


def b64d(v):
    return base64.b64decode(v)


def b64e(b):
    if isinstance(b, str):
        b = b.encode("utf-8")
    return base64.b64encode(b).decode("ascii")


def ok(**kw):
    kw["ok"] = True
    return kw


def fail(code, msg, **kw):
    kw.update(ok=False, code=code, msg=str(msg))
    return kw


def message(dn, attrs, flag):
    msg = ldb.Message()
    msg.dn = ldb.Dn(db, dn)
    for name, vals in attrs.items():
        msg[name] = ldb.MessageElement([b64d(v) for v in vals], flag, name)
    return msg


def entry_to_json(res):
    attrs = {}
    for name in res.keys():
        if name.lower() == "dn":
            continue
        attrs[name] = [b64e(v) for v in res[name]]
    return {"dn": str(res.dn), "attrs": attrs}


def rid_of(sid_bytes):
    """Extract the RID from an objectSid (binary). Raise if it differs from the domain SID."""
    sid = ndr_unpack(security.dom_sid, sid_bytes)
    text = str(sid)
    prefix, _, rid = text.rpartition("-")
    if prefix != DOMAIN_SID:
        raise ValueError("objectSid %s does not belong to this lab's domain (%s)" % (text, DOMAIN_SID))
    return int(rid)


def op_hello(req):
    global FAST, SERVER
    FAST = bool(req.get("fast_password"))
    SERVER = bool(req.get("server_attributes"))
    # Try the same operation up front so the import does not fail midway (the transaction is cancelled, so nothing remains).
    ver = getattr(samba, "version", "")  # samba.version is a string
    guid = uuid.uuid4()
    sid = "%s-%d" % (DOMAIN_SID, 2147000000 + (guid.int % 1000))
    db.transaction_start()
    try:
        msg = ldb.Message()
        msg.dn = ldb.Dn(db, "CN=ldap-cronin-selfcheck,CN=Users," + BASE)
        msg["objectClass"] = ldb.MessageElement([b"user"], ldb.FLAG_MOD_ADD, "objectClass")
        msg["sAMAccountName"] = ldb.MessageElement([b"adckselfchk"], ldb.FLAG_MOD_ADD, "sAMAccountName")
        msg["objectGUID"] = ldb.MessageElement([ndr_pack(misc.GUID(str(guid)))], ldb.FLAG_MOD_ADD, "objectGUID")
        msg["objectSid"] = ldb.MessageElement([ndr_pack(security.dom_sid(sid))], ldb.FLAG_MOD_ADD, "objectSid")
        try:
            db.add(msg, controls=CONTROLS)
        except ldb.LdbError as e:
            return fail(e.args[0], "self-check: add with a specified objectGUID was rejected (not usable with this Samba): %s" % e.args[1])
        res = db.search(base=msg.dn, scope=ldb.SCOPE_BASE, attrs=["objectGUID"])
        got = str(ndr_unpack(misc.GUID, res[0]["objectGUID"][0]))
        if got != str(guid):
            return fail(1, "self-check: objectGUID did not take the specified value (%s != %s)" % (got, guid))
        if SERVER:
            given = {"whenCreated": [b"20010203040506.0Z"], "lastLogonTimestamp": [b"133000000000000000"],
                     "sIDHistory": [ndr_pack(security.dom_sid("S-1-5-21-1-2-3-4567"))]}
            try:
                set_server_attrs(str(msg.dn), given)
            except ldb.LdbError as e:
                return fail(e.args[0], "self-check: the source's server attributes were rejected (server_attributes = \"source\" is not usable with this Samba): %s" % e.args[1])
            res = db.search(base=msg.dn, scope=ldb.SCOPE_BASE, attrs=list(given))[0]
            for name, values in given.items():
                if name not in res or [bytes(v) for v in res[name]] != values:
                    return fail(1, "self-check: %s did not take the value given: server_attributes = \"source\" is not usable with this Samba" % name)
        if FAST:
            nt_hash = bytes(range(1, 17))
            try:
                set_nt_hash(str(msg.dn), nt_hash)
            except ldb.LdbError as e:
                return fail(e.args[0], "self-check: writing an NT hash directly was rejected (fast_password is not usable with this Samba): %s" % e.args[1])
            if read_nt_hash(str(msg.dn)) != nt_hash:
                return fail(1, "self-check: an NT hash written directly was not kept (fast_password is not usable with this Samba)")
    finally:
        db.transaction_cancel()
    return ok(samba=str(ver), tested=str(ver).startswith(TESTED_SAMBA_PREFIX), base=BASE, domain_sid=DOMAIN_SID,
              domain_guid=str(ndr_unpack(misc.GUID, db.search(base=BASE, scope=ldb.SCOPE_BASE, attrs=["objectGUID"])[0]["objectGUID"][0])))


def op_get(req):
    try:
        res = db.search(base=ldb.Dn(db, req["dn"]), scope=ldb.SCOPE_BASE, attrs=req.get("attrs") or ["*"])
    except ldb.LdbError as e:
        if e.args[0] == ldb.ERR_NO_SUCH_OBJECT:
            return ok(entry=None)
        raise
    return ok(entry=entry_to_json(res[0]) if len(res) else None)


def op_search(req):
    scope = {"base": ldb.SCOPE_BASE, "one": ldb.SCOPE_ONELEVEL}.get(req.get("scope"), ldb.SCOPE_SUBTREE)
    try:
        res = db.search(base=ldb.Dn(db, req["base"]), scope=scope, expression=req.get("filter") or "(objectClass=*)",
                        attrs=req.get("attrs") or ["*"])
    except ldb.LdbError as e:
        if e.args[0] == ldb.ERR_NO_SUCH_OBJECT:
            return ok(entries=[])
        raise
    return ok(entries=[entry_to_json(r) for r in res])


def add_entry(dn, attrs, controls):
    """Add an entry. At an add, samldb refuses a computer's sAMAccountName without a trailing $ unless the requester is
    in BUILTIN\\Administrators, which the system session is not (an Administrator over LDAP is let through); AD
    names the loser of a sAMAccountName conflict $DUPLICATE-<n>, a computer's too. Such an entry is added through a
    session of the domain's administrators instead (measured on 4.19.5: it takes the same controls, objectGUID and
    objectSid; appending a $ and renaming it after is refused the same way)."""
    try:
        db.add(message(dn, attrs, ldb.FLAG_MOD_ADD), controls=controls)
    except ldb.LdbError as e:
        if e.args[0] != ldb.ERR_UNWILLING_TO_PERFORM or "trailing $" not in str(e.args[1]):
            raise
        admin_db().add(message(dn, attrs, ldb.FLAG_MOD_ADD), controls=controls)


_admin_db = None


def admin_db():
    global _admin_db
    if _admin_db is None:
        _admin_db = SamDB(url="/var/lib/samba/private/sam.ldb", session_info=admin_session(lp, db.get_domain_sid()), lp=lp)
    return _admin_db


def op_add(req):
    global max_rid, server_count
    attrs = dict(req["attrs"])
    server = {}
    for name in list(attrs):
        if name.lower() in SERVER_LOWER:
            server[name] = [b64d(v) for v in attrs.pop(name)]
    controls = []
    if "objectGUID" in attrs or "objectSid" in attrs:
        controls = CONTROLS
    if "objectSid" in attrs:
        rid = rid_of(b64d(attrs["objectSid"][0]))
    else:
        rid = 0
    try:
        add_entry(req["dn"], attrs, controls)
    except ldb.LdbError as e:
        if e.args[0] == ldb.ERR_CONSTRAINT_VIOLATION and rid:
            # The objectSid is the cause only when another object holds it; samldb refuses a userPrincipalName or
            # servicePrincipalName in use with the same code, and naming the SID then sends the reader the wrong way.
            # A deleted object keeps its objectSid, so it is searched too.
            sid = ndr_unpack(security.dom_sid, b64d(attrs["objectSid"][0]))
            found = db.search(base=BASE, scope=ldb.SCOPE_SUBTREE, expression="(objectSid=%s)" % sid, attrs=["distinguishedName"],
                              controls=["show_deleted:1", "show_recycled:1"])
            if len(found) or "index violation on objectSid" in str(e.args[1]):
                owners = ", ".join(str(r.dn) for r in found)
                return fail(e.args[0], "objectSid %s collided with an existing object in the lab (%s): %s" % (sid, owners or "unknown", e.args[1]))
        if e.args[0] == ldb.ERR_CONSTRAINT_VIOLATION:
            return fail(e.args[0], "the lab refused %s: %s" % (req["dn"], e.args[1]))
        raise
    max_rid = max(max_rid, rid)
    if SERVER and server:
        set_server_attrs(req["dn"], server)
        server_count += 1
    return ok()


def op_replace(req):
    attrs = dict(req["attrs"])
    pwd = attrs.pop("unicodePwd", None)
    if pwd:
        # unicodePwd is UTF-16LE wrapped in quotes. Locally it is set via setpassword (LDAPS is not needed).
        text = b64d(pwd[0]).decode("utf-16-le")
        if len(text) < 2 or text[0] != '"' or text[-1] != '"':
            return fail(19, "unicodePwd is not wrapped in quotes")
        set_password(req["dn"], text[1:-1])
    sd = attrs.pop("nTSecurityDescriptor", None)
    if attrs:
        db.modify(message(req["dn"], attrs, ldb.FLAG_MOD_REPLACE))
    if sd:
        # The owner, the group and the DACL only, as the source was read (its SACL is not read): Samba keeps them,
        # and computes the inherited ACEs from the object's parents, as it does when a parent's descriptor changes.
        db.modify(message(req["dn"], {"nTSecurityDescriptor": sd}, ldb.FLAG_MOD_REPLACE), controls=["sd_flags:1:7"])
    return ok()


def set_password(dn, password):
    global fast_count
    if FAST and password in nt_hashes:
        set_nt_hash(dn, nt_hashes[password])
        fast_count += 1
        return
    # setpassword also enables the account and drops PASSWD_NOTREQD (measured on 4.19.5: 546 becomes 512), which a
    # password set over LDAP leaves as it is. clone sets the password again on every run of an account that must
    # change it (pwdLastSet 0) and compares userAccountControl with what it read before, so a disabled account came
    # out enabled on every other run; it is put back as it was.
    uac = read_uac(dn)
    db.setpassword("(distinguishedName=%s)" % ldb.binary_encode(dn), password, False)
    if uac is not None and read_uac(dn) != uac:
        db.modify(message(dn, {"userAccountControl": [b64e(uac)]}, ldb.FLAG_MOD_REPLACE))
    if FAST:
        nt_hash = read_nt_hash(dn)
        if nt_hash:
            nt_hashes[password] = nt_hash


def read_uac(dn):
    res = db.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["userAccountControl"])
    return res[0]["userAccountControl"][0] if "userAccountControl" in res[0] else None


def read_nt_hash(dn):
    res = db.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["unicodePwd"], controls=["search_options:1:2"])
    return res[0]["unicodePwd"][0] if "unicodePwd" in res[0] else None


def set_nt_hash(dn, nt_hash):
    """Write an NT hash as it is, and pwdLastSet as setpassword sets it (now): the bypass control makes the password
    module take unicodePwd as a hash and derive nothing from it."""
    msg = ldb.Message()
    msg.dn = ldb.Dn(db, dn)
    msg["unicodePwd"] = ldb.MessageElement([nt_hash], ldb.FLAG_MOD_REPLACE, "unicodePwd")
    nttime = int((time.time() + 11644473600) * 10000000)  # 100ns since 1601-01-01
    msg["pwdLastSet"] = ldb.MessageElement([str(nttime).encode()], ldb.FLAG_MOD_REPLACE, "pwdLastSet")
    db.modify(msg, controls=["local_oid:%s:0" % dsdb.DSDB_CONTROL_BYPASS_PASSWORD_HASH_OID] + CONTROLS)


def op_add_values(req):
    db.modify(message(req["dn"], {req["attr"]: req["values"]}, ldb.FLAG_MOD_ADD))
    return ok()


def op_delete_values(req):
    db.modify(message(req["dn"], {req["attr"]: req["values"]}, ldb.FLAG_MOD_DELETE))
    return ok()


# The journal of a run done in slices (clone -time-limit): the keys of the objects done and the largest RID imported,
# in the lab's volume so that a snapshot carries exactly the progress its data has. Its first line is the
# fingerprint of the source and config it is valid for.
JOURNAL = "/var/lib/samba/ldap-cronin-journal"


def op_journal_load(req):
    """Read the journal if it is for this fingerprint; otherwise start one for it. The largest RID it recorded joins max_rid."""
    global max_rid
    keys = []
    try:
        with open(JOURNAL, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        lines = []
    if lines and lines[0] == "fp " + req["fingerprint"]:
        for line in lines[1:]:
            kind, _, rest = line.partition(" ")
            if kind == "k":
                keys.append(rest)
            elif kind == "rid" and rest.isdigit():
                max_rid = max(max_rid, int(rest))
        return ok(keys=keys, stale=False)
    with open(JOURNAL, "w", encoding="utf-8") as f:
        f.write("fp " + req["fingerprint"] + "\n")
        f.flush()
        os.fsync(f.fileno())
    return ok(keys=[], stale=bool(lines))


def op_journal_add(req):
    """Append keys done, and the largest RID imported so far (a resumed run skips the objects that hold the others)."""
    with open(JOURNAL, "a", encoding="utf-8") as f:
        for key in req["keys"]:
            f.write("k " + key + "\n")
        f.write("rid %d\n" % max_rid)
        f.flush()
        os.fsync(f.fileno())
    return ok()


def op_journal_clear(_req):
    try:
        os.remove(JOURNAL)
    except FileNotFoundError:
        pass
    return ok()


def op_finish(req):
    """Post-import cleanup. Advance the RID allocation past the largest imported RID and verify consistency with dbcheck
    (left out at the end of a slice: it reads the whole database, and the last slice runs it)."""
    bumped = None
    if max_rid:
        bumped = bump_rid(max_rid)
    if req.get("dbcheck") is False:
        if req.get("complete"):
            # dbcheck left out by [target.lab] dbcheck = "skip": the import is complete all the same.
            op_journal_clear(req)
        return ok(max_rid=max_rid, rid_next=bumped, dbcheck="", fast_passwords=fast_count, server_attributes=server_count)
    proc = subprocess.run(["samba-tool", "dbcheck", "--cross-ncs"], capture_output=True, text=True)
    out = (proc.stdout + proc.stderr).strip().splitlines()
    summary = out[-1] if out else ""
    if proc.returncode != 0 or ", 0 errors" not in summary and "(0 errors)" not in summary:
        return fail(1, "dbcheck reported an error (relax loosens the consistency checks, so this is the last line of defense): " + " / ".join(out[-5:]))
    # The import is complete: the next one compares everything again (the source may have been dumped anew). Here,
    # once dbcheck has passed, and not before it: an interrupted dbcheck then leaves the journal, and the next run
    # skips every object. Here also because the helper ends after this answer.
    op_journal_clear(req)
    return ok(max_rid=max_rid, rid_next=bumped, dbcheck=summary, fast_passwords=fast_count, server_attributes=server_count)


def bump_rid(maximum):
    """Advance rIDNextRID and rIDAllocationPool of the RID Set past maximum (so the imported RIDs do not collide with new allocations)."""
    res = db.search(base=BASE, scope=ldb.SCOPE_SUBTREE, expression="(objectClass=rIDSet)",
                    attrs=["rIDAllocationPool", "rIDNextRID"])
    if not len(res):
        raise RuntimeError("RID Set not found")
    rs = res[0]
    nxt = int(rs["rIDNextRID"][0]) if "rIDNextRID" in rs else 0
    pool = int(rs["rIDAllocationPool"][0])
    low, high = pool & 0xFFFFFFFF, pool >> 32
    if nxt > maximum:
        return nxt
    new_next = maximum + 1
    new_high = max(high, new_next + 499)
    msg = ldb.Message()
    msg.dn = rs.dn
    msg["rIDNextRID"] = ldb.MessageElement([str(new_next).encode()], ldb.FLAG_MOD_REPLACE, "rIDNextRID")
    msg["rIDAllocationPool"] = ldb.MessageElement([str(new_next | (new_high << 32)).encode()], ldb.FLAG_MOD_REPLACE, "rIDAllocationPool")
    db.modify(msg, controls=["provision:0", "relax:0"])
    return new_next


OPS = {"hello": op_hello, "get": op_get, "search": op_search, "add": op_add, "replace": op_replace,
       "add_values": op_add_values, "delete_values": op_delete_values, "finish": op_finish, "journal_load": op_journal_load,
       "journal_add": op_journal_add, "journal_clear": op_journal_clear}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = {}
        try:
            req = json.loads(line)
            resp = OPS[req["op"]](req)
        except ldb.LdbError as e:
            resp = fail(e.args[0], e.args[1])
        except Exception as e:  # noqa: BLE001
            traceback.print_exc()
            resp = fail(-1, "%s: %s" % (type(e).__name__, e))
        proto.write(json.dumps(resp, ensure_ascii=True) + "\n")
        proto.flush()
        if req.get("op") == "finish":
            break


main()
