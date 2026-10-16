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
import traceback
import uuid

# Duplicate the protocol's stdout, then redirect later print and library output to stderr.
proto = os.fdopen(os.dup(1), "w", buffering=1)
sys.stdout = sys.stderr

import ldb  # noqa: E402
import samba  # noqa: E402
from samba.auth import system_session  # noqa: E402
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


def op_hello(_req):
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
        db.add(msg, controls=CONTROLS)
        res = db.search(base=msg.dn, scope=ldb.SCOPE_BASE, attrs=["objectGUID"])
        got = str(ndr_unpack(misc.GUID, res[0]["objectGUID"][0]))
        if got != str(guid):
            return fail(1, "self-check: objectGUID did not take the specified value (%s != %s)" % (got, guid))
    except ldb.LdbError as e:
        return fail(e.args[0], "self-check: add with a specified objectGUID was rejected (not usable with this Samba): %s" % e.args[1])
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


def op_add(req):
    global max_rid
    attrs = req["attrs"]
    controls = []
    if "objectGUID" in attrs or "objectSid" in attrs:
        controls = CONTROLS
    if "objectSid" in attrs:
        rid = rid_of(b64d(attrs["objectSid"][0]))
    else:
        rid = 0
    try:
        db.add(message(req["dn"], attrs, ldb.FLAG_MOD_ADD), controls=controls)
    except ldb.LdbError as e:
        if e.args[0] == ldb.ERR_CONSTRAINT_VIOLATION and rid:
            # An object with the same RID already exists. Without knowing which one collided, the cause is hard to trace.
            sid = ndr_unpack(security.dom_sid, b64d(attrs["objectSid"][0]))
            found = db.search(base=BASE, scope=ldb.SCOPE_SUBTREE, expression="(objectSid=%s)" % sid, attrs=["distinguishedName"])
            owners = ", ".join(str(r.dn) for r in found)
            return fail(e.args[0], "objectSid %s collided with an existing object in the lab (%s): %s" % (sid, owners or "unknown", e.args[1]))
        raise
    max_rid = max(max_rid, rid)
    return ok()


def op_replace(req):
    attrs = dict(req["attrs"])
    pwd = attrs.pop("unicodePwd", None)
    if pwd:
        # unicodePwd is UTF-16LE wrapped in quotes. Locally it is set via setpassword (LDAPS is not needed).
        text = b64d(pwd[0]).decode("utf-16-le")
        if len(text) < 2 or text[0] != '"' or text[-1] != '"':
            return fail(19, "unicodePwd is not wrapped in quotes")
        db.setpassword("(distinguishedName=%s)" % ldb.binary_encode(req["dn"]), text[1:-1], False)
    if attrs:
        db.modify(message(req["dn"], attrs, ldb.FLAG_MOD_REPLACE))
    return ok()


def op_add_values(req):
    db.modify(message(req["dn"], {req["attr"]: req["values"]}, ldb.FLAG_MOD_ADD))
    return ok()


def op_finish(_req):
    """Post-import cleanup. Advance the RID allocation past the largest imported RID and verify consistency with dbcheck."""
    bumped = None
    if max_rid:
        bumped = bump_rid(max_rid)
    proc = subprocess.run(["samba-tool", "dbcheck", "--cross-ncs"], capture_output=True, text=True)
    out = (proc.stdout + proc.stderr).strip().splitlines()
    summary = out[-1] if out else ""
    if proc.returncode != 0 or ", 0 errors" not in summary and "(0 errors)" not in summary:
        return fail(1, "dbcheck reported an error (relax loosens the consistency checks, so this is the last line of defense): " + " / ".join(out[-5:]))
    return ok(max_rid=max_rid, rid_next=bumped, dbcheck=summary)


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
       "add_values": op_add_values, "finish": op_finish}


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
