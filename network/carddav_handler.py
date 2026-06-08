import os
from network.dav_xml_builder import build_propfind, build_report


class CardDAVHandler:
    """CardDAV 联系人请求处理"""

    @staticmethod
    def do_GET(handler):
        path = handler.path
        svc = handler.contact_service
        if path.endswith(".vcf"):
            uid = os.path.basename(path).replace(".vcf", "")
            vcard = svc.get_by_uid(uid)
            if vcard:
                handler.send_response(200)
                handler.send_header('Content-type', 'text/vcard')
                handler.send_header('ETag', svc.get_etag(uid) or '')
                handler.end_headers()
                handler.wfile.write(vcard.encode('utf-8'))
            else:
                handler._send_error(404, "Contact not found")
        elif path == "/contacts/":
            handler.send_response(200)
            handler.send_header('Content-type', 'text/directory')
            handler.end_headers()
            for vcard in svc.get_all_raw():
                handler.wfile.write(vcard.encode('utf-8'))
                handler.wfile.write(b"\n")
        else:
            handler._send_error(404)

    @staticmethod
    def do_PUT(handler, data):
        uid = os.path.basename(handler.path).replace(".vcf", "")
        handler.contact_service.add_contact(data)
        handler.send_response(201)
        handler.send_header('Content-type', 'text/plain')
        handler.send_header('ETag', handler.contact_service.get_etag(uid) or '')
        handler.end_headers()
        handler.wfile.write(f"Contact {uid} created/updated".encode())

    @staticmethod
    def do_POST(handler, data):
        uid = os.path.basename(handler.path).replace(".vcf", "")
        handler.contact_service.add_contact(data)
        handler.send_response(201)
        handler.send_header('Content-type', 'text/plain')
        handler.end_headers()
        handler.wfile.write(f"Contact {uid} created".encode())

    @staticmethod
    def do_DELETE(handler):
        uid = os.path.basename(handler.path).replace(".vcf", "")
        if handler.contact_service.delete(uid):
            handler.send_response(204)
            handler.end_headers()
        else:
            handler._send_error(404, "Contact not found")

    @staticmethod
    def do_HEAD(handler):
        uid = os.path.basename(handler.path).replace(".vcf", "")
        vcard = handler.contact_service.get_by_uid(uid)
        if vcard:
            handler.send_response(200)
            handler.send_header('Content-type', 'text/vcard')
            handler.send_header('Content-Length', str(len(vcard.encode('utf-8'))))
            handler.send_header('ETag', handler.contact_service.get_etag(uid) or '')
            handler.end_headers()
        else:
            handler._send_error(404, "Contact not found")

    @staticmethod
    def do_PROPFIND(handler, depth, is_collection):
        return build_propfind(
            handler, handler.contact_service,
            'xmlns:C="urn:ietf:params:xml:ns:carddav"', '<C:addressbook/>',
            ".vcf", "text/vcard", depth, is_collection
        )

    @staticmethod
    def do_REPORT(handler, hrefs):
        return build_report(handler, hrefs, handler.contact_service, ".vcf", "text/vcard")
