import os
from services.settings_service import SettingsService
from network.dav_xml_builder import build_propfind, build_report


class CalDAVHandler:
    """CalDAV 日历事件请求处理"""

    @staticmethod
    def _get_attachment_config(handler):
        ss = SettingsService()
        mode = ss.get_setting("attachment_mode", "inline")
        scheme = "https" if getattr(handler.server, 'sslmode', False) else "http"
        host = handler.headers.get('Host', f"localhost:{handler.server.server_address[1]}")
        base_url = f"{scheme}://{host}"
        return mode, base_url

    @staticmethod
    def do_GET(handler):
        path = handler.path
        svc = handler.event_service
        mode, base_url = CalDAVHandler._get_attachment_config(handler)
        if path.endswith(".ics"):
            uid = os.path.basename(path).replace(".ics", "")
            full_ical = svc.get_full_ical(uid, mode, base_url)
            if full_ical:
                handler.send_response(200)
                handler.send_header('Content-type', 'text/calendar')
                handler.send_header('ETag', svc.get_etag(uid) or '')
                handler.send_header('Content-Length', str(len(full_ical.encode('utf-8'))))
                handler.end_headers()
                handler.wfile.write(full_ical.encode('utf-8'))
        elif path == "/events/":
            handler.send_response(200)
            handler.send_header('Content-type', 'text/calendar')
            handler.end_headers()
            all_events = svc.get_all_full_raw(mode, base_url)
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
        mode, base_url = CalDAVHandler._get_attachment_config(handler)
        full_ical = handler.event_service.get_full_ical(uid, mode, base_url)
        if full_ical:
            handler.send_response(200)
            handler.send_header('Content-type', 'text/calendar')
            handler.send_header('Content-Length', str(len(full_ical.encode('utf-8'))))
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
