"""测试 DAV 协议端点 — PROPFIND / REPORT / 基本 CRUD"""
import sys, time, json
sys.path.insert(0, '.')
import httpx
from database.db_manager import Database
from network.dav_server import DAVServer, DAVHandler
from threading import Thread

DAV_PORT = 8098
BASE = f"http://127.0.0.1:{DAV_PORT}"
errors = []

def check(name, ok, detail=""):
    tag = "PASS" if ok else "FAIL"
    print(f"  {tag}  {name}  {detail}")
    if not ok:
        errors.append(name)

def main():
    srv = DAVServer(DAV_PORT)
    t = Thread(target=srv.start, daemon=True)
    t.start()
    time.sleep(0.5)

    # 准备测试联系人
    db = Database()
    db.execute("DELETE FROM contacts WHERE uid='test-dav-proto'")
    db.execute(
        "INSERT OR REPLACE INTO contacts (uid, full_name, email, phone, vcard, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("test-dav-proto", "DAV Test", "dav@test.com", "",
         "BEGIN:VCARD\nVERSION:3.0\nUID:test-dav-proto\nFN:DAV Test\nEMAIL:dav@test.com\nEND:VCARD",
         time.strftime("%Y-%m-%dT%H:%M:%S"), time.strftime("%Y-%m-%dT%H:%M:%S"))
    )

    client = httpx.Client()

    def xml_body(data):
        return '<?xml version="1.0" encoding="utf-8"?>\n' + data, "application/xml; charset=utf-8"

    print("\n=== PROPFIND ===")
    body, ctype = xml_body('<D:propfind xmlns:D="DAV:"><D:prop><D:displayname/><D:getcontenttype/><D:resourcetype/></D:prop></D:propfind>')
    r = client.request("PROPFIND", BASE, content=body, headers={"Content-Type": ctype, "Depth": "0"})
    check("PROPFIND / 200", r.status_code == 207, f"status={r.status_code}")

    body, ctype = xml_body('<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav"><D:prop><D:displayname/><C:addressbook-home-set/><D:resourcetype/></D:prop></D:propfind>')
    r = client.request("PROPFIND", f"{BASE}/contacts/", content=body, headers={"Content-Type": ctype, "Depth": "0"})
    check("PROPFIND /contacts/ 207", r.status_code == 207, f"status={r.status_code}")

    print("\n=== GET /contacts/ ===")
    r = client.get(f"{BASE}/contacts/")
    check("GET /contacts/ 200", r.status_code == 200, f"status={r.status_code}")

    print("\n=== OPTIONS ===")
    r = client.options(BASE)
    check("OPTIONS / 200", r.status_code == 200, f"status={r.status_code}")

    print("\n=== HEAD ===")
    r = client.head(f"{BASE}/contacts/test-dav-proto.vcf")
    check("HEAD contact 200", r.status_code == 200, f"status={r.status_code}")

    print("\n=== GET vCard ===")
    r = client.get(f"{BASE}/contacts/test-dav-proto.vcf")
    check("GET vCard 200", r.status_code == 200, f"status={r.status_code}")
    check("GET vCard 含 FN", "FN:DAV Test" in r.text, "")

    print("\n=== DELETE ===")
    r = client.delete(f"{BASE}/contacts/test-dav-proto.vcf")
    check("DELETE 204", r.status_code == 204, f"status={r.status_code}")

    print("\n=== PUT ===")
    vcard = "BEGIN:VCARD\nVERSION:3.0\nUID:test-dav-put\nFN:PUT Test\nEND:VCARD"
    r = client.put(f"{BASE}/contacts/test-dav-put.vcf", content=vcard,
                   headers={"Content-Type": "text/vcard"})
    check("PUT 201", r.status_code == 201, f"status={r.status_code}")
    r = client.get(f"{BASE}/contacts/test-dav-put.vcf")
    check("PUT 验证", r.status_code == 200 and "PUT Test" in r.text, f"status={r.status_code}")
    client.delete(f"{BASE}/contacts/test-dav-put.vcf")

    db.execute("DELETE FROM contacts WHERE uid='test-dav-proto'")
    db.execute("DELETE FROM contacts WHERE uid='test-dav-put'")
    srv.stop()
    client.close()
    print(f"\n{'='*40}")
    if errors:
        print(f"!!! {len(errors)} 个检查失败:")
        for e in errors:
            print(f"  - {e}")
    else:
        print("所有 DAV 协议测试通过")
    return 1 if errors else 0

if __name__ == "__main__":
    sys.exit(main())
