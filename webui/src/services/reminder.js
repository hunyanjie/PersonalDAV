import api from '../api.js'

const CHECK_INTERVAL = 60000
const LOOKAHEAD_MINUTES = 15
const _notified = new Set()

function pad(n) {
  return String(n).padStart(2, '0')
}

function toYMD(d) {
  return `${d.getFullYear()}${pad(d.getMonth()+1)}${pad(d.getDate())}`
}

function toISO(d) {
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}:00`
}

function parseDT(raw) {
  raw = raw.replace('T', ' ').split('+')[0].split('Z')[0].trim()
  const m = Date.parse(raw.replace(' ', 'T'))
  return isNaN(m) ? null : new Date(m)
}

let _timer = null

export function startReminderCheck() {
  if (!('Notification' in window)) return
  if (Notification.permission === 'default') {
    Notification.requestPermission()
  }
  stopReminderCheck()
  check()
  _timer = setInterval(check, CHECK_INTERVAL)
}

export function stopReminderCheck() {
  if (_timer) { clearInterval(_timer); _timer = null }
}

async function check() {
  if (Notification.permission !== 'granted') return
  const now = new Date()
  const later = new Date(now.getTime() + LOOKAHEAD_MINUTES * 60000)
  const dateFrom = toYMD(now)
  const dateTo = toYMD(new Date(later.getTime() + 86400000))

  try {
    const data = await api.listEvents(0, 200, dateFrom, dateTo)
    const items = data.items || []
    const nowMs = now.getTime()
    const laterMs = later.getTime()

    for (const ev of items) {
      if (!ev.uid || _notified.has(ev.uid)) continue
      const start = parseDT(ev.dtstart)
      if (!start) continue
      const startMs = start.getTime()
      if (startMs >= nowMs && startMs <= laterMs) {
        _notified.add(ev.uid)
        try {
          const n = new Notification('即将开始的日程', {
            body: `${ev.summary || '(无标题)'}\n开始时间: ${start.toLocaleTimeString('zh-CN', {hour:'2-digit',minute:'2-digit'})}`,
            icon: '/icons/icon.svg',
          })
          setTimeout(() => n.close(), 8000)
        } catch (e) {
          // 通知失败静默处理
        }
      }
    }
  } catch (e) {
    // 网络错误静默处理（离线时不报错）
  }
}
