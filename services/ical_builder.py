import re
import vobject
import pytz
import base64
import os
from datetime import datetime, timedelta
from dateutil import parser
from models.constants import (
    STANDARD_ICAL_FIELDS, STATUS_MAPPING, STATUS_REV_MAPPING,
    TRANSPARENCY_MAPPING, TRANSPARENCY_REV_MAPPING,
    FREQ_MAPPING, ALARM_ACTION_REV_MAPPING,
)
from config import SOFTWARE_NAME, SOFTWARE_VERSION
from utils.encoding_helper import decode_ical_value
from utils import attachment_store


def parse_ical_event(ical_string):
    """解析 iCal 字符串为结构化表单数据"""
    data = {}
    try:
        ical = vobject.readOne(ical_string)
        ev = ical.vevent if ical.name == 'VCALENDAR' else ical
        if hasattr(ev, 'summary'):
            data['summary'] = decode_ical_value(ev.summary.value)
        if hasattr(ev, 'location'):
            data['location'] = decode_ical_value(ev.location.value)
        if hasattr(ev, 'description'):
            data['description'] = decode_ical_value(ev.description.value)
        if hasattr(ev, 'categories'):
            raw = ev.categories.value
            data['categories'] = decode_ical_value(
                ",".join(raw) if isinstance(raw, list) else raw)
        if hasattr(ev, 'priority'):
            data['priority'] = int(ev.priority.value)
        if hasattr(ev, 'organizer'):
            data['organizer'] = decode_ical_value(ev.organizer.value)
        if hasattr(ev, 'status'):
            data['status'] = ev.status.value
        if hasattr(ev, 'url'):
            data['url'] = decode_ical_value(ev.url.value)
        if hasattr(ev, 'sequence'):
            data['sequence'] = str(ev.sequence.value)
        if 'x-force-reminder' in ev.contents:
            data['force_reminder'] = ev.contents['x-force-reminder'][0].value == "1"
        if 'x-sync-tz' in ev.contents:
            data['sync_tz'] = ev.contents['x-sync-tz'][0].value == "1"
        if 'x-allday' in ev.contents:
            data['allday'] = ev.contents['x-allday'][0].value == "1"

        data['attendees'] = _parse_attendees(ev)
        data['other_fields'] = _parse_other_fields(ev)

        _parse_dtstart(ev, data)
        _parse_dtend(ev, data)
        _parse_rrule(ev, data)
        _parse_exdate(ev, data)
        data['attachments'] = _parse_attachments(ev)
        data['alarms'] = _parse_alarms(ev)
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"解析 iCalendar 失败: {e}")
    return data


def _parse_attendees(ev):
    values = set()
    if hasattr(ev, 'attendee_list'):
        for a in ev.attendee_list:
            values.add(decode_ical_value(a.value))
    elif hasattr(ev, 'attendee'):
        values.add(decode_ical_value(ev.attendee.value))
    return sorted(values) if values else []


def _parse_other_fields(ev):
    fields = []
    for child in ev.contents.values():
        for item in child:
            name = item.name.upper()
            if name not in STANDARD_ICAL_FIELDS:
                fields.append({"key": name, "value": str(item.value)})
    return fields


def _parse_dtstart(ev, data):
    if not hasattr(ev, 'dtstart'):
        return
    dt = ev.dtstart.value
    if isinstance(dt, datetime):
        data['dtstart'] = dt
        if 'TZID' in ev.dtstart.params:
            data['start_tzid'] = ev.dtstart.params['TZID'][0]
    else:
        data['dtstart'] = dt
        data['allday'] = True


def _parse_dtend(ev, data):
    if not hasattr(ev, 'dtend'):
        return
    dt = ev.dtend.value
    if isinstance(dt, datetime):
        data['dtend'] = dt
        if 'TZID' in ev.dtend.params:
            data['end_tzid'] = ev.dtend.params['TZID'][0]
    else:
        data['dtend'] = dt - timedelta(days=1)


def _parse_rrule(ev, data):
    if not hasattr(ev, 'rrule'):
        return
    rrule_str = ev.rrule.value
    parts = dict(item.split('=') for item in rrule_str.split(';') if '=' in item)
    freq = parts.get('FREQ')
    interval = parts.get('INTERVAL', '1')
    if freq == 'DAILY' and interval == '1':
        data['repeat'] = '每天'
    elif freq == 'WEEKLY' and interval == '1':
        data['repeat'] = '每周'
    elif freq == 'WEEKLY' and interval == '2':
        data['repeat'] = '每两周'
    elif freq == 'MONTHLY' and interval == '1':
        data['repeat'] = '每月'
    elif freq == 'YEARLY' and interval == '1':
        data['repeat'] = '每年'
    else:
        data['repeat'] = '自定义'
        data['custom_repeat'] = {'freq': freq, 'interval': interval}
    if 'UNTIL' in parts:
        data['end_cond'] = '按日期结束'
        try:
            data['end_date'] = parser.parse(parts['UNTIL']).date()
        except Exception:
            pass
    elif 'COUNT' in parts:
        data['end_cond'] = '按次数结束'
        data['end_count'] = parts['COUNT']
    else:
        data['end_cond'] = '永不结束'


def _parse_exdate(ev, data):
    exdates = []
    if 'exdate' in ev.contents:
        for ex in ev.contents['exdate']:
            val = ex.value
            if isinstance(val, list):
                for v in val:
                    exdates.append(v.strftime('%Y-%m-%d') if isinstance(v, datetime) else str(v))
            elif isinstance(val, datetime):
                exdates.append(val.strftime('%Y-%m-%d'))
            else:
                exdates.append(str(val))
    data['exdates'] = exdates


def _parse_attachments(ev):
    attachments = []
    seen_inline = set()
    seen_uri = set()
    if 'attach' in ev.contents:
        for att in ev.contents['attach']:
            a = {'inline': False}
            if hasattr(att, 'encoding_param') and att.encoding_param == 'BASE64':
                a['inline'] = True
                a['data'] = att.value
                a['filename'] = att.params.get('FILENAME', ['attachment.bin'])[0] if hasattr(att, 'params') else 'attachment.bin'
                a['fmttype'] = att.params.get('FMTTYPE', ['application/octet-stream'])[0] if hasattr(att, 'params') else 'application/octet-stream'
                a['size'] = int(len(base64.b64decode(a['data'])) * 3 / 4) if a['data'] else 0
                key = a['data']
                if key in seen_inline:
                    continue
                seen_inline.add(key)
            else:
                raw = att.value
                if len(raw) > 100 and '://' not in raw and not raw.startswith('www.'):
                    continue
                if raw in seen_uri:
                    continue
                seen_uri.add(raw)
                a['uri'] = raw
                a['filename'] = att.params.get('FILENAME', [raw])[0] if hasattr(att, 'params') else raw
                a['fmttype'] = att.params.get('FMTTYPE', ['text/uri-list'])[0] if hasattr(att, 'params') else 'text/uri-list'
                a['size'] = 0
            attachments.append(a)
    if 'x-personaldav-attach' in ev.contents:
        for xatt in ev.contents['x-personaldav-attach']:
            a = {'inline': True}
            a['filepath'] = xatt.params.get('X-FILEPATH', [''])[0]
            a['filename'] = xatt.params.get('FILENAME', ['attachment.bin'])[0]
            a['fmttype'] = xatt.params.get('FMTTYPE', ['application/octet-stream'])[0]
            a['size'] = int(xatt.params.get('X-SIZE', ['0'])[0])
            attachments.append(a)
    return attachments


def _parse_alarms(ev):
    alarms = []
    valarms = ev.contents.get('valarm', [])
    if not valarms:
        valarms = [c for c in ev.getChildren() if c.name.upper() == 'VALARM']
    for alarm in valarms:
        trigger = alarm.trigger.value if hasattr(alarm, 'trigger') else None
        if trigger is None:
            continue
        alarm_data = {'action': alarm.action.value if hasattr(alarm, 'action') else 'DISPLAY', 'trigger': trigger}
        if hasattr(alarm, 'attach'): alarm_data['attach'] = alarm.attach.value
        if hasattr(alarm, 'summary'): alarm_data['summary'] = alarm.summary.value
        if hasattr(alarm, 'description'): alarm_data['description'] = alarm.description.value
        if hasattr(alarm, 'attendee'): alarm_data['attendee'] = alarm.attendee.value
        if hasattr(alarm, 'repeat'):
            try:
                alarm_data['repeat'] = int(alarm.repeat.value)
            except Exception:
                pass
        if hasattr(alarm, 'duration'): alarm_data['duration'] = alarm.duration.value
        alarms.append(alarm_data)
    return alarms


def build_ical(form_data):
    """将表单数据构建为 iCal 字符串"""
    cal = vobject.iCalendar()
    cal.add('version').value = form_data.get('version', '2.0')
    cal.add('prodid').value = f"-//{SOFTWARE_NAME}//{SOFTWARE_VERSION}//ZH-CN"
    ev = cal.add('vevent')
    ev.add('uid').value = form_data['uid']
    ev.add('summary').value = form_data['summary']

    if form_data.get('location'):
        ev.add('location').value = form_data['location']
    description = form_data.get('description', '')
    if description:
        ev.add('description').value = description
    ev.add('status').value = form_data.get('status', 'CONFIRMED')

    _build_dt(ev, form_data)
    _build_rrule(ev, form_data)
    _build_exdates(ev, form_data)
    _build_alarms(ev, form_data)
    _build_attachments(ev, form_data)
    _build_extra_fields(ev, form_data)

    return cal.serialize()


def _build_dt(ev, data):
    allday = data.get('allday', False)
    if allday:
        ev.add('dtstart').value = data['start_date']
        ev.add('dtend').value = data['end_date'] + timedelta(days=1)
        ev.add('X-ALLDAY').value = "1"
    else:
        s_tz = pytz.timezone(data.get('start_tzid', 'UTC'))
        e_tz = pytz.timezone(data.get('end_tzid', 'UTC'))
        ev.add('dtstart').value = s_tz.localize(data['start_datetime'])
        ev.add('dtend').value = e_tz.localize(data['end_datetime'])
        if s_tz.zone != "UTC":
            ev.dtstart.params['TZID'] = [s_tz.zone]
        if e_tz.zone != "UTC":
            ev.dtend.params['TZID'] = [e_tz.zone]


def _build_rrule(ev, data):
    r_opt = data.get('repeat', '不重复')
    if r_opt == '不重复':
        return
    rrule = FREQ_MAPPING.get(r_opt, '')
    if r_opt == '自定义' and data.get('custom_repeat'):
        cr = data['custom_repeat']
        rrule = f"FREQ={cr['freq']};INTERVAL={cr['interval']}"
    if not rrule:
        return
    cond = data.get('end_cond', '永不结束')
    if cond == '按日期结束':
        rrule += f";UNTIL={data['end_date_entry'].strftime('%Y%m%dT235959Z')}"
    elif cond == '按次数结束':
        rrule += f";COUNT={data.get('end_count', '5')}"
    ev.add('rrule').value = rrule


def _build_exdates(ev, data):
    exdates = data.get('exdates', [])
    if not exdates:
        return
    allday = data.get('allday', False)
    tz_id = None
    if not allday:
        tz_id = data.get('start_tzid')
    for d in exdates:
        ex = ev.add('exdate')
        dt = datetime.strptime(d, '%Y-%m-%d')
        if allday:
            ex.value = [dt.date()]
        elif tz_id:
            ex.value = [pytz.timezone(tz_id).localize(dt)]
            ex.params['TZID'] = [tz_id]
        else:
            ex.value = [dt]


def _build_alarms(ev, data):
    from datetime import timedelta as td
    for a in data.get('alarms', []):
        al = ev.add('valarm')
        al.add('action').value = a['action']
        al.add('trigger').value = a['trigger']
        if 'description' in a:
            al.add('description').value = a['description']
        if 'attach' in a:
            al.add('attach').value = a['attach']
        if 'attendee' in a:
            al.add('attendee').value = a['attendee']
        if 'summary' in a:
            al.add('summary').value = a['summary']
        if 'repeat' in a:
            al.add('repeat').value = str(a['repeat'])
            al.add('duration').value = a['duration']


def _build_attachments(ev, data):
    for a in data.get('attachments', []):
        if a.get('inline'):
            filepath = a.get('filepath', '')
            if not filepath:
                b64_data = a.get('data', '')
                if not b64_data:
                    continue
                record = attachment_store.from_base64(b64_data, a.get('filename', 'attachment.bin'), a.get('fmttype'))
                if '_b64_fallback' in record:
                    att = ev.add('attach')
                    att.value = b64_data
                    att.encoding_param = 'BASE64'
                    att.encoded = True
                    att.params['VALUE'] = ['BINARY']
                    if a.get('fmttype') and a['fmttype'] != 'application/octet-stream':
                        att.params['FMTTYPE'] = [a['fmttype']]
                    if a.get('filename'):
                        att.params['FILENAME'] = [a['filename']]
                    continue
                a['filepath'] = record['filepath']
                a['size'] = record['size']
            xatt = ev.add('x-personaldav-attach')
            xatt.value = 'REF'
            if a.get('fmttype'):
                xatt.params['FMTTYPE'] = [a['fmttype']]
            if a.get('filename'):
                xatt.params['FILENAME'] = [a['filename']]
            if a.get('filepath'):
                xatt.params['X-FILEPATH'] = [a['filepath']]
            xatt.params['X-SIZE'] = [str(a.get('size', 0))]
        else:
            att = ev.add('attach')
            att.value = a.get('uri', '')
            if a.get('fmttype') and a['fmttype'] != 'text/uri-list':
                att.params['FMTTYPE'] = [a['fmttype']]


def inject_attachments(stored_ical: str, mode: str = "inline", base_url: str = "") -> str:
    if 'X-PERSONALDAV-ATTACH' not in stored_ical:
        return stored_ical
    try:
        cal = vobject.readOne(stored_ical)
        ev = cal.vevent if cal.name == 'VCALENDAR' else cal
        if 'x-personaldav-attach' not in ev.contents:
            return stored_ical
        for xatt in list(ev.contents['x-personaldav-attach']):
            filepath = xatt.params.get('X-FILEPATH', [''])[0]
            filename = xatt.params.get('FILENAME', ['attachment.bin'])[0]
            fmttype = xatt.params.get('FMTTYPE', ['application/octet-stream'])[0]
            att = ev.add('attach')

            if mode == "uri" and base_url:
                rel_path = os.path.basename(filepath) if filepath else filename
                att.value = f"{base_url.rstrip('/')}/attachments/{rel_path}"
                if fmttype and fmttype != 'application/octet-stream':
                    att.params['FMTTYPE'] = [fmttype]
                if filename:
                    att.params['FILENAME'] = [filename]
            else:
                record = {'filepath': filepath, 'filename': filename, 'fmttype': fmttype}
                b64_data = attachment_store.to_base64(record)
                if b64_data is None:
                    continue
                att.value = b64_data
                att.encoding_param = 'BASE64'
                att.encoded = True
                att.params['VALUE'] = ['BINARY']
                if fmttype and fmttype != 'application/octet-stream':
                    att.params['FMTTYPE'] = [fmttype]
                if filename:
                    att.params['FILENAME'] = [filename]
            ev.contents['x-personaldav-attach'].remove(xatt)
        serialized = cal.serialize()
        serialized = re.sub(
            r'^X-PERSONALDAV-ATTACH[^\r\n]*(?:\r?\n[ \t][^\r\n]*)*\r?\n',
            '', serialized, flags=re.MULTILINE
        )
        return serialized
    except Exception:
        import logging
        logging.getLogger(__name__).exception("注入附件失败")
        return stored_ical


def _build_extra_fields(ev, data):
    ev.add('priority').value = str(data.get('priority', 5))
    ev.add('transp').value = data.get('transparency', 'OPAQUE')
    if data.get('organizer'):
        ev.add('organizer').value = str(data['organizer'])
    try:
        seq = int(data.get('sequence', '0'))
        if data.get('is_edit'):
            seq += 1
        ev.add('sequence').value = str(seq)
    except Exception:
        pass
    if data.get('url', '').strip():
        ev.add('url').value = data['url'].strip()
    if data.get('categories'):
        ev.add('categories').value = data['categories']
    if data.get('force_reminder'):
        ev.add('x-force-reminder').value = "1"
    if data.get('sync_tz'):
        ev.add('x-sync-tz').value = "1"
    for line in data.get('attendees', []):
        if line.strip():
            ev.add('attendee').value = line.strip()
    for field in data.get('other_fields', []):
        k = field.get('key', '').strip()
        v = field.get('value', '').strip()
        if k and k.upper() not in STANDARD_ICAL_FIELDS:
            try:
                ev.add(k.lower()).value = v
            except Exception:
                pass
