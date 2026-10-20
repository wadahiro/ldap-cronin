"""Write Exchange's schema to the domain just provisioned, before Samba starts.

The image carries the schema files of Exchange's setup when it was built with them (make image EXCHANGE_ISO=...):
the series /PrepareSchema applies to a forest with no Exchange whose schema is Windows Server 2003 or later, as
Samba's is (PostWindows2003_schema0.ldf to ..99.ldf), then SchemaVersion.ldf. This writes them as /PrepareSchema
would, straight into the database: over LDAP the same took minutes, as Samba checks the schema at every change;
here it takes seconds.

The changes go in rounds of one transaction. Samba sees a definition only after the transaction that adds it is
committed, so a change naming one added in the same round fails; it is tried again in the next round, and the
later changes of the same entry wait with it, so they keep their order. It stops when every change is in, or when a
round adds nothing: what is left then is printed and the exit status is 1, so the lab does not start half made.

Usage: exchange-schema.py <directory of the .ldf files> <base DN of the domain>
"""
import os
import re
import sys
import time

import ldb
from samba.auth import system_session
from samba.param import LoadParm
from samba.samdb import SamDB

SERIES = re.compile(r"^PostWindows2003_schema(\d+)\.ldf$", re.IGNORECASE)
VERSION = "schemaversion.ldf"

# The fields of a class that may name the class itself: Windows takes that in the add that creates the class, Samba
# refuses it (the class does not exist yet), so the value is added once the class is in.
SELF_REF = ("possSuperiors", "systemPossSuperiors", "auxiliaryClass", "systemAuxiliaryClass")


def files(directory):
    """The series by number, then SchemaVersion.ldf."""
    series, version = [], None
    for name in os.listdir(directory):
        m = SERIES.match(name)
        if m:
            series.append((int(m.group(1)), name))
        elif name.lower() == VERSION:
            version = name
    if not series:
        sys.exit("exchange-schema: no PostWindows2003_schema*.ldf in %s" % directory)
    names = [n for _, n in sorted(series)]
    return names + ([version] if version else [])


def to_ldif(text, schema_dn):
    """An ldifde file as plain LDIF: CRLF, comments and the #! directives of Microsoft's tools, the schema naming
    context written <SchemaContainerDN>, the ntdsSchema changetypes; the root DSE records (schemaUpgradeInProgress,
    schemaUpdateNow) are left out, as the rounds commit instead."""
    out = []
    for record in text.replace("\r\n", "\n").split("\n\n"):
        lines = [l for l in record.split("\n") if l and not l.startswith("#")]
        if not lines or lines[0].strip() == "dn:":
            continue
        lines = [l.replace("<SchemaContainerDN>", schema_dn) for l in lines]
        lines = ["changetype: add" if l == "changetype: ntdsSchemaAdd"
                 else "changetype: modify" if l == "changetype: ntdsSchemaModify" else l for l in lines]
        out.append("\n".join(lines))
    return "\n\n".join(out) + "\n"


def raw(el):
    """The values of an element as bytes (str() fails on a binary one, schemaIdGuid)."""
    return [el.get(i) if isinstance(el.get(i), bytes) else el.get(i).encode() for i in range(len(el))]


def changes(db, directory, schema_dn):
    ops, later = [], []
    for name in files(directory):
        with open(os.path.join(directory, name), encoding="utf-8", errors="replace") as f:
            text = to_ldif(f.read(), schema_dn)
        for changetype, msg in db.parse_ldif(text):
            if changetype == ldb.CHANGETYPE_ADD and "governsID" in msg:
                own = {raw(msg["lDAPDisplayName"])[0].lower(), raw(msg["governsID"])[0].lower()}
                for field in SELF_REF:
                    if field not in msg:
                        continue
                    values = raw(msg[field])
                    mine = [v for v in values if v.lower() in own]
                    if not mine:
                        continue
                    rest = [v for v in values if v.lower() not in own]
                    del msg[field]
                    if rest:
                        msg[field] = ldb.MessageElement(rest, ldb.FLAG_MOD_ADD, field)
                    m = ldb.Message(msg.dn)
                    m[field] = ldb.MessageElement(mine, ldb.FLAG_MOD_ADD, field)
                    later.append(("modify", m))
            ops.append(("add" if changetype == ldb.CHANGETYPE_ADD else "modify", msg))
    return ops + later


def modify(db, msg):
    """A modify, field by field: an add sends only the values missing, one by one, as the server takes a value given
    as an OID for one it holds by name; a delete of what is not there changes nothing."""
    for name in msg.keys():
        if name == "dn":
            continue
        el = msg[name]
        flag, values = el.flags(), raw(el)
        if flag == ldb.FLAG_MOD_ADD:
            res = db.search(base=msg.dn, scope=ldb.SCOPE_BASE, attrs=[name])
            have = {v.lower() for v in raw(res[0][name])} if len(res) and name in res[0] else set()
            for v in values:
                if v.lower() in have:
                    continue
                m = ldb.Message(msg.dn)
                m[name] = ldb.MessageElement([v], ldb.FLAG_MOD_ADD, name)
                try:
                    db.modify(m)
                except ldb.LdbError as e:
                    if e.args[0] != ldb.ERR_ATTRIBUTE_OR_VALUE_EXISTS:
                        raise
            continue
        m = ldb.Message(msg.dn)
        m[name] = ldb.MessageElement(values, flag, name)
        try:
            db.modify(m)
        except ldb.LdbError as e:
            if not (flag == ldb.FLAG_MOD_DELETE and e.args[0] == ldb.ERR_NO_SUCH_ATTRIBUTE):
                raise


def main(directory, base_dn):
    started = time.time()
    lp = LoadParm()
    lp.load("/etc/samba/smb.conf")
    lp.set("dsdb:schema update allowed", "true")
    lp.set("ldb:nosync", "true")
    db = SamDB(url="/var/lib/samba/private/sam.ldb", session_info=system_session(), lp=lp)
    pending = changes(db, directory, "CN=Schema,CN=Configuration," + base_dn)
    total, rounds, errors = len(pending), 0, {}
    while pending:
        rounds += 1
        db.transaction_start()
        failed, blocked = [], set()
        for kind, msg in pending:
            dn = str(msg.dn).lower()
            if dn in blocked:
                failed.append((kind, msg))
                continue
            try:
                if kind == "add":
                    db.add(msg)
                else:
                    modify(db, msg)
            except ldb.LdbError as e:
                if kind == "add" and e.args[0] == ldb.ERR_ENTRY_ALREADY_EXISTS:
                    continue  # Windows' later base schema, which Samba has (ms-DS-Phonetic-*, ...)
                failed.append((kind, msg))
                blocked.add(dn)
                errors[dn] = e.args[1]
        db.transaction_commit()
        if len(failed) == len(pending):
            print("exchange-schema: %d of %d changes cannot be written:" % (len(failed), total), file=sys.stderr)
            for _, msg in failed:
                dn = str(msg.dn)
                print("  %s: %s" % (dn, errors.get(dn.lower(), "")), file=sys.stderr)
            sys.exit(1)
        pending = failed
    print("exchange-schema: %d changes in %d rounds, %.1fs" % (total, rounds, time.time() - started))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
