import os
from network.dav_xml_builder import build_propfind, build_report


class CalDAVHandler:
    """CalDAV 日历事件请求处理"""

    @staticmethod
    def do_GET(handler):
        path = handler.path
        svc = handler.event_service
        if path.endswith(".ics"):
            uid = os.path.basename(path).replace(".ics", "")
            event = svc.get_by_uid(uid)
            if event:
                handler.send_response(200)
                handler.send_header('Content-type', 'text/calendar')
                handler.send_header('ETag', svc.get_etag(uid) or '')
                handler.end_headers()
                handler.wfile.write(event.encode('utf-8'))
        elif path == "/events/":
            handler.send_response(200)
            handler.send_header('Content-type', 'text/calendar')
            handler.end_headers()
            all_events = svc.get_all_raw()
            calendar_data = svc.combine_raw_events(all_events)
            handler.wfile.write(calendar_data.encode('utf-8'))
        else:
            handler._send_error(404, "Event not found")

    @staticmethod
    def do_PUT(handler, data):
        uid = os.path.basename(handler.path).replace(".ics", "")
        handler.event_service.add_event(data)
        handler.send_response(201)
        handler.send_header('Content-type', 'text/plain')
        handler.send_header('ETag', handler.event_service.get_etag(uid) or '')
        handler.end_headers()
        handler.wfile.write(f"Event {uid} created/updated".encode())

    @staticmethod
    def do_POST(handler, data):
        uid = os.path.basename(handler.path).replace(".ics", "")
        handler.event_service.add_event(data)
        handler.send_response(201)
        handler.send_header('Content-type', 'text/plain')
        handler.end_headers()
        handler.wfile.write(f"Event {uid} created".encode())

    @staticmethod
    def do_DELETE(handler):
        uid = os.path.basename(handler.path).replace(".ics", "")
        if handler.event_service.delete(uid):
            handler.send_response(204)
            handler.end_headers()
        else:
            handler._send_error(404, "Event not found")

    @staticmethod
    def do_HEAD(handler):
        uid = os.path.basename(handler.path).replace(".ics", "")
        event = handler.event_service.get_by_uid(uid)
        if event:
            handler.send_response(200)
            handler.send_header('Content-type', 'text/calendar')
            handler.send_header('Content-Length', str(len(event.encode('utf-8'))))
            handler.send_header('ETag', handler.event_service.get_etag(uid) or '')
            handler.end_headers()
        else:
            handler._send_error(404, "Event not found")

    @staticmethod
    def do_PROPFIND(handler, depth, is_collection):
        return build_propfind(
            handler, handler.event_service,
            'xmlns:C="urn:ietf:params:xml:ns:caldav"', '<C:calendar/>',
            ".ics", "text/calendar", depth, is_collection
        )

    @staticmethod
    def do_REPORT(handler, hrefs):
        return build_report(handler, hrefs, handler.event_service, ".ics", "text/calendar")
