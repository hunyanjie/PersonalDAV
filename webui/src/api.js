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
    throw new Error('密码错误或未登录')
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    const error = new Error(body.detail || `请求失败 (${res.status})`)
    error.status = res.status
    throw error
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
  createContact(data) { return request('POST', '/contacts', { body: data }) },
  updateContact(uid, data) { return request('PUT', `/contacts/${uid}`, { body: data }) },
  deleteContact(uid) { return request('DELETE', `/contacts/${uid}`) },
  importContactVcf(vcardData) { return request('POST', '/contacts/import', { body: { vcard_data: vcardData } }) },
  searchContacts(q, offset = 0, limit = 50) { return request('GET', '/contacts/search', { params: qs({ q, offset, limit }) }) },

  // Events
  listEvents(offset = 0, limit = 50, dateFrom = '', dateTo = '') { return request('GET', '/events', { params: qs({ offset, limit, date_from: dateFrom, date_to: dateTo }) }) },
  getEvent(uid) { return request('GET', `/events/${uid}`) },
  createEvent(data) { return request('POST', '/events', { body: data }) },
  updateEvent(uid, data) { return request('PUT', `/events/${uid}`, { body: data }) },
  deleteEvent(uid) { return request('DELETE', `/events/${uid}`) },
  importEventIcs(icalData) { return request('POST', '/events/import', { body: { ical_data: icalData } }) },
  searchEvents(q, dateFrom = '', dateTo = '', offset = 0, limit = 200) {
    return request('GET', '/events/search', { params: qs({ q, date_from: dateFrom, date_to: dateTo, offset, limit }) })
  },

  // Trash
  listTrash() { return request('GET', '/trash') },
  restoreTrash(uuid, targetPath = '', conflictStrategy = 'error') {
    return request('POST', '/trash/restore', { params: qs({ uuid, target_path: targetPath, conflict_strategy: conflictStrategy }) })
  },
  deleteTrashItem(uuid) { return request('DELETE', '/trash', { params: { uuid } }) },
  purgeTrash(days = 0) { return request('POST', '/trash/purge', { params: { days } }) },

  // Auth tokens
  listApiTokens() { return request('GET', '/auth/tokens') },
  createApiToken(scopes, note, expiresAt) { return request('POST', '/auth/tokens', { body: { scopes, note, expires_at: expiresAt } }) },
  deleteApiToken(id) { return request('DELETE', `/auth/tokens/${id}`) },
  updateTokenNote(id, note) { return request('PUT', `/auth/tokens/${id}/note`, { body: { note } }) },

  // Files
  listFiles(path = '/') { return request('GET', '/files', { params: { path } }) },
  uploadFile(file, path = '/', overwrite = false) {
    const t = token()
    const form = new FormData()
    form.append('file', file)
    form.append('path', path)
    form.append('overwrite', overwrite ? 'True' : 'False')
    return fetch(`${BASE}/files/upload`, {
      method: 'POST',
      headers: t ? { Authorization: `Bearer ${t}` } : {},
      body: form,
    }).then(r => r.json())
  },
  uploadFileWithProgress(file, path = '/', onProgress, overwrite = false, filename = null) {
    return new Promise((resolve, reject) => {
      const t = token()
      const form = new FormData()
      form.append('file', file, filename || file.name)
      form.append('path', path)
      form.append('overwrite', overwrite ? 'True' : 'False')
      const xhr = new XMLHttpRequest()
      xhr.open('POST', `${BASE}/files/upload`)
      if (t) xhr.setRequestHeader('Authorization', `Bearer ${t}`)
      xhr.upload.onprogress = e => {
        if (e.lengthComputable && onProgress) onProgress(Math.round((e.loaded / e.total) * 100))
      }
      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          try {
            resolve(JSON.parse(xhr.responseText))
          } catch(e) {
            reject(new Error("服务器响应格式错误"))
          }
        }
        else reject(new Error(`上传失败 (${xhr.status})`))
      }
      xhr.onerror = () => reject(new Error('网络错误'))
      xhr.send(form)
    })
  },
  downloadUrl(path) {
    const t = token()
    return `${BASE}/files/download?path=${encodeURIComponent(path)}${t ? `&token=${t}` : ''}`
  },
  previewUrl(path) {
    const t = token()
    return `${BASE}/files/preview?path=${encodeURIComponent(path)}${t ? `&token=${t}` : ''}`
  },
  async previewFile(path) {
    const t = token()
    const url = `${BASE}/files/preview?path=${encodeURIComponent(path)}`
    const headers = t ? { Authorization: `Bearer ${t}` } : {}
    const res = await fetch(url, { headers })
    if (!res.ok) throw new Error('预览请求失败')
    const blob = await res.blob()
    return URL.createObjectURL(blob)
  },
  renameFile(path, newName) {
    return request('PUT', '/files/rename', { params: qs({ path, new_name: newName }) })
  },
  deleteFile(path) { return request('DELETE', '/files', { params: { path } }) },
  mkdir(path) { return request('POST', '/files/mkdir', { params: { path } }) },

  // Mounts
  listMounts() { return request('GET', '/files/mounts') },
  addMount(name, path) { return request('POST', '/files/mounts', { body: { name, path } }) },
  updateMount(name, newName, newPath) { return request('PUT', `/files/mounts/${encodeURIComponent(name)}`, { body: { name: newName, path: newPath } }) },
  deleteMount(name) { return request('DELETE', `/files/mounts/${encodeURIComponent(name)}`) },

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
  systemLogs() { return request('GET', '/logs') },
  health() { return request('GET', '/health') },
  async downloadAppleConfig(host) {
    const t = token()
    const url = `${BASE}/apple/config?host=${encodeURIComponent(host)}`
    const headers = t ? { Authorization: `Bearer ${t}` } : {}
    const res = await fetch(url, { headers })
    if (!res.ok) throw new Error('下载失败')
    const blob = await res.blob()
    const dlUrl = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = dlUrl; a.download = 'personaldav.mobileconfig'; a.click()
    URL.revokeObjectURL(dlUrl)
  },
  get(path) { return request('GET', path) },
  post(path, body) { return request('POST', path, { body }) },
  put(path, body) { return request('PUT', path, { body }) },
  delete(path) { return request('DELETE', path) },
}
