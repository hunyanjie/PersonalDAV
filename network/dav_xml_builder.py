import os
import hashlib


def resource_xml(href, rtype_xml, etag_val, ctype_val, res_size):
    return f"""    <D:response>
        <D:href>{href}</D:href>
        <D:propstat>
            <D:prop>
                <D:resourcetype>{rtype_xml}</D:resourcetype>
                <D:getetag>{etag_val}</D:getetag>
                <D:getcontenttype>{ctype_val}</D:getcontenttype>
                <D:getcontentlength>{res_size}</D:getcontentlength>
            </D:prop>
            <D:status>HTTP/1.1 200 OK</D:status>
        </D:propstat>
    </D:response>"""


def collection_response(href, rtype, etag, ctag_val, ctype):
    return f"""    <D:response>
        <D:href>{href}</D:href>
        <D:propstat>
            <D:prop>
                <D:resourcetype>{rtype}</D:resourcetype>
                <D:getetag>{etag}</D:getetag>
                <D:getcontenttype>{ctype}</D:getcontenttype>
                <D:getcontentlength>0</D:getcontentlength>
                <getctag xmlns="http://calendarserver.org/ns/">{ctag_val}</getctag>
            </D:prop>
            <D:status>HTTP/1.1 200 OK</D:status>
        </D:propstat>
    </D:response>"""


def report_ok_response(href, etag, ctype, length):
    return f"""    <D:response>
        <D:href>{href}</D:href>
        <D:propstat>
            <D:prop>
                <D:getetag>{etag}</D:getetag>
                <D:getcontenttype>{ctype}</D:getcontenttype>
                <D:getcontentlength>{length}</D:getcontentlength>
            </D:prop>
            <D:status>HTTP/1.1 200 OK</D:status>
        </D:propstat>
    </D:response>"""


def report_not_found(href):
    return f"""    <D:response>
        <D:href>{href}</D:href>
        <D:status>HTTP/1.1 404 Not Found</D:status>
    </D:response>"""


def wrap_multistatus(responses, ns=''):
    xml = f"""<?xml version="1.0" encoding="utf-8" ?>
<D:multistatus xmlns:D="DAV:" {ns}>
{chr(10).join(responses)}
</D:multistatus>"""
    return xml.encode('utf-8')


def build_propfind(handler, svc, ns, rtype, ext, ctype, depth, is_collection):
    """构建 PROPFIND 多状态响应 — 用于 CardDAV / CalDAV 集合"""
    responses = []
    if is_collection:
        etag = svc.get_etag("") or '"dummy"'
        ctag_val = handler._collection_ctag(svc)
        responses.append(collection_response(handler.path, rtype, etag, ctag_val, ctype))
        if depth != '0':
            for uid, raw in svc.get_all_items():
                child_href = f"{handler.path}{uid}{ext}"
                child_etag = svc.get_etag(uid) or f'"{hashlib.md5(raw.encode("utf-8")).hexdigest()}"'
                responses.append(resource_xml(child_href, '', child_etag, ctype, str(len(raw.encode('utf-8')))))
    else:
        uid = os.path.basename(handler.path).replace(ext, '')
        etag_val = svc.get_etag(uid) or '""'
        responses.append(resource_xml(handler.path, '', etag_val, ctype, "0"))
    return wrap_multistatus(responses, ns)


def build_report(handler, hrefs, svc, ext, ctype):
    """构建 REPORT 批量查询响应 — 用于 CardDAV / CalDAV"""
    responses = []
    for href in hrefs:
        uid = os.path.basename(href).replace(ext, "")
        raw = svc.get_by_uid(uid)
        if raw:
            etag = svc.get_etag(uid) or f'"{hashlib.md5(raw.encode("utf-8")).hexdigest()}"'
            responses.append(report_ok_response(href, etag, ctype, len(raw.encode("utf-8"))))
        else:
            responses.append(report_not_found(href))
    return wrap_multistatus(responses)
