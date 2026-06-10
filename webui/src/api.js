const BASE = '/api'

function token() {
  return localStorage.getItem('token') || ''
}

async function request(method, path, options = {}) {
  const headers = { 'Content-Type': 'application/json' }
  const t = token()
  if (t) headers['Authorization'] = `Bearer ${t}`

  const body = options.body ? JSON.stringify(options.body) : undefined
  const params = options.params ? '?' + new URLSearchParams(options.params).toString() : ''

  const res = await fetch(`${BASE}${path}${params}`, { method, headers, body })
  if (res.status === 401 || res.status === 403) {
    localStorage.removeItem('token')
    window.location.hash = '#/login'
    throw new Error('未登录')
  }
  const ct = res.headers.get('content-type') || ''
  if (ct.includes('application/json')) {
    return res.json()
  }
  return res
}

function qs(params) {
  return Object.fromEntries(
    Object.entries(params).filter(([_, v]) => v !== '' && v !== null && v !== undefined)
  )
}

export default {
  // Auth
  login(password, fingerprint = '') {
    return request('POST', '/auth/token', { body: { password, fingerprint } })
  },

  // Contacts
  listContacts(offset = 0, limit = 50) { return request('GET', '/contacts', { params: { offset, limit } }) },
  getContact(uid) { return request('GET', `/contacts/${uid}`) },
  createContact(vcardData) { return request('POST', '/contacts', { body: { vcard_data: vcardData } }) },
  createContactStructured(data) { return request('POST', '/contacts/structured', { body: data }) },
  updateContact(uid, vcardData) { return request('PUT', `/contacts/${uid}`, { body: { vcard_data: vcardData } }) },
  deleteContact(uid) { return request('DELETE', `/contacts/${uid}`) },
  searchContacts(q, limit = 10) { return request('GET', '/contacts/search', { params: qs({ q, limit }) }) },

  // Events
  listEvents(offset = 0, limit = 50, dateFrom = '', dateTo = '') { return request('GET', '/events', { params: qs({ offset, limit, date_from: dateFrom, date_to: dateTo }) }) },
  getEvent(uid) { return request('GET', `/events/${uid}`) },
  createEvent(icalData) { return request('POST', '/events', { body: { ical_data: icalData } }) },
  updateEvent(uid, icalData) { return request('PUT', `/events/${uid}`, { body: { ical_data: icalData } }) },
  deleteEvent(uid) { return request('DELETE', `/events/${uid}`) },
  searchEvents(q, dateFrom = '', dateTo = '', limit = 10) {
    return request('GET', '/events/search', { params: qs({ q, date_from: dateFrom, date_to: dateTo, limit }) })
  },

  // Files
  listFiles(path = '/') { return request('GET', '/files', { params: { path } }) },
  uploadFile(file, path = '/') {
    const t = token()
    const form = new FormData()
    form.append('file', file)
    form.append('path', path)
    return fetch(`${BASE}/files/upload`, {
      method: 'POST',
      headers: t ? { Authorization: `Bearer ${t}` } : {},
      body: form,
    }).then(r => r.json())
  },
  downloadUrl(path) {
    const t = token()
    return `${BASE}/files/download?path=${encodeURIComponent(path)}${t ? `&token=${t}` : ''}`
  },
  previewUrl(path) {
    const t = token()
    return `${BASE}/files/preview?path=${encodeURIComponent(path)}${t ? `&token=${t}` : ''}`
  },
  renameFile(path, newName) {
    return request('PUT', '/files/rename', { params: qs({ path, new_name: newName }) })
  },
  deleteFile(path) { return request('DELETE', '/files', { params: { path } }) },
  mkdir(path) { return request('POST', '/files/mkdir', { params: { path } }) },

  // Settings
  listSettings() { return request('GET', '/settings') },
  getSetting(key) { return request('GET', `/settings/${key}`) },
  updateSetting(key, value) { return request('PUT', `/settings/${key}`, { body: { value } }) },

  // Server
  serverConfig() { return request('GET', '/server/config') },
  stats() { return request('GET', '/stats') },
  authLogs(limit = 100, protocol = '') {
    return request('GET', '/auth/logs', { params: qs({ limit, protocol }) })
  },
  health() { return request('GET', '/health') },
}
