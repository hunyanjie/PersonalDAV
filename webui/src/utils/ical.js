import { pad } from './format.js'

export const PRODID = 'PRODID:-//PersonalDAV//CN'

export function icalDateToObj(s) {
  if (!s) return null
  if (s.length <= 8) {
    return new Date(parseInt(s.substring(0,4)), parseInt(s.substring(4,6)) - 1, parseInt(s.substring(6,8)))
  }
  const y = parseInt(s.substring(0,4)), m = parseInt(s.substring(4,6)) - 1, d = parseInt(s.substring(6,8))
  const h = parseInt(s.substring(9,11) || '0'), min = parseInt(s.substring(11,13) || '0'), sec = parseInt(s.substring(13,15) || '0')
  return new Date(y, m, d, h, min, sec)
}

export function formatTime(s) {
  const d = icalDateToObj(s)
  return d ? d.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' }) : ''
}

export function formatDateFull(s) {
  const d = icalDateToObj(s)
  return d ? d.toLocaleDateString('zh-CN', { year: 'numeric', month: 'long', day: 'numeric', weekday: 'long' }) : ''
}

export function eventStatus(e, now) {
  if (!e || !e.dtstart) return ''
  const st = icalDateToObj(e.dtstart)
  const et = icalDateToObj(e.dtend)
  if (!st) return ''
  if (!et || now > et) return 'ended'
  if (now >= st) return 'ongoing'
  return 'upcoming'
}

export function parseAttachments(ical) {
  const results = []
  const lines = (ical || '').split(/\r?\n/)
  const unfolded = []
  for (let i = 0; i < lines.length; i++) {
    if (i > 0 && lines[i].startsWith(' ')) unfolded[unfolded.length - 1] += lines[i].substring(1)
    else unfolded.push(lines[i])
  }
  for (const line of unfolded) {
    if (!line.toUpperCase().includes('ATTACH')) continue
    const parts = line.split(':'), head = parts[0], val = parts.slice(1).join(':')
    let fileName = '附件'
    const nameMatch = head.match(/FILENAME=([^;]+)/i)
    if (nameMatch) fileName = decodeURIComponent(nameMatch[1].trim())
    else fileName = val.split('/').pop().split('\\').pop() || '附件'
    if (head.toUpperCase().includes('ENCODING=BASE64')) {
      const typeMatch = head.match(/FMTTYPE=(.*?)(;|$)/i)
      const mime = typeMatch ? typeMatch[1] : 'application/octet-stream'
      results.push({ name: decodeURIComponent(fileName), url: `data:${mime};base64,${val}` })
    } else {
      results.push({ name: decodeURIComponent(fileName), url: val })
    }
  }
  return results
}

export function toICS(events) {
  const vevents = events.map(e => [
    'BEGIN:VEVENT', `UID:${e.uid || ''}`,
    `DTSTART:${(e.dtstart || '').replace(/[-:]/g, '')}`,
    `DTEND:${(e.dtend || '').replace(/[-:]/g, '')}`,
    `SUMMARY:${e.summary || ''}`,
    e.description ? `DESCRIPTION:${e.description}` : '',
    e.location ? `LOCATION:${e.location}` : '',
    e.categories ? `CATEGORIES:${e.categories}` : '',
    'END:VEVENT',
  ].filter(Boolean).join('\r\n')).join('\r\n')
  return `BEGIN:VCALENDAR\r\nVERSION:2.0\r\n${PRODID}\r\n${vevents}\r\nEND:VCALENDAR`
}

export function downloadIcs(content, name) {
  const blob = new Blob([content], { type: 'text/calendar;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = name; a.click(); URL.revokeObjectURL(url)
}

export const REPEAT_OPTIONS = ['不重复', '每日', '每周', '每月', '每年']
export const REPEAT_END_OPTIONS = ['永不结束', '次数', '日期']
export const WEEKDAYS = ['MO', 'TU', 'WE', 'TH', 'FR', 'SA', 'SU']
export const FREQ_MAP = { '每日': 'DAILY', '每周': 'WEEKLY', '每月': 'MONTHLY', '每年': 'YEARLY' }