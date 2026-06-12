<template>
  <div class="form-card">
    <h3>{{ isNew ? '新建事件' : '编辑事件' }}</h3>
    <form @submit.prevent="save">
      <label>标题</label>
      <input v-model="form.summary" required />
      <label>分类（逗号分隔）</label>
      <input v-model="form.categories" placeholder="MEETING,WORK" />
      <label>地点</label>
      <input v-model="form.location" />
      <label><input type="checkbox" v-model="form.allDay" /> 全天事件</label>
      <label>开始时间</label>
      <input v-model="form.dtstart" :type="form.allDay ? 'date' : 'datetime-local'" required />
      <label>结束时间</label>
      <input v-model="form.dtend" :type="form.allDay ? 'date' : 'datetime-local'" required />
      <label>描述</label>
      <textarea v-model="form.description" rows="4"></textarea>
      <div class="form-actions">
        <button type="submit" class="btn-primary" :disabled="saving">{{ saving ? '保存中...' : '保存' }}</button>
        <router-link to="/calendar" class="btn-cancel">取消</router-link>
      </div>
    </form>
  </div>
</template>

<script>
import api from '../api.js'

function toLocalISO(d) {
  if (!d) return ''
  const pad = n => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

function toDateStr(d) {
  const pad = n => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}`
}

function getField(lines, key) {
  for (const l of lines) {
    if (l.toUpperCase().startsWith(key + ':') || l.toUpperCase().startsWith(key + ';'))
      return l.split(':').slice(1).join(':').trim()
  }
  return ''
}

function setVeventField(lines, key, value) {
  const ukey = key.toUpperCase()
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].toUpperCase().startsWith(ukey + ':') || lines[i].toUpperCase().startsWith(ukey + ';')) {
      if (value) lines[i] = key + ':' + value
      else lines.splice(i, 1)
      return
    }
  }
  if (value) {
    const ins = lines.findIndex(l => l.toUpperCase() === 'END:VEVENT')
    if (ins >= 0) lines.splice(ins, 0, key + ':' + value)
    else lines.push(key + ':' + value)
  }
}

export default {
  data: () => ({
    form: { summary: '', dtstart: '', dtend: '', description: '', categories: '', location: '', allDay: false },
    saving: false, isNew: true, loadedUid: null, _rawIcal: '',
  }),
  async mounted() {
    const uid = this.$route.params.uid
    if (uid) {
      this.isNew = false; this.loadedUid = uid
      try {
        const e = await api.getEvent(uid)
        this._rawIcal = e.ical || ''
        const lines = this._rawIcal.split('\n')
        this.form.summary = getField(lines, 'SUMMARY') || ''
        this.form.description = getField(lines, 'DESCRIPTION') || ''
        this.form.categories = getField(lines, 'CATEGORIES') || ''
        this.form.location = getField(lines, 'LOCATION') || ''

        const rawStart = getField(lines, 'DTSTART')
        const rawEnd = getField(lines, 'DTEND')
        if (rawStart) {
          const isAllDay = rawStart.length === 8
          this.form.allDay = isAllDay
          if (isAllDay) {
            this.form.dtstart = `${rawStart.substring(0,4)}-${rawStart.substring(4,6)}-${rawStart.substring(6,8)}`
          } else {
            const s = new Date(rawStart.substring(0,4)+'-'+rawStart.substring(4,6)+'-'+rawStart.substring(6,8)+'T'+rawStart.substring(9,11)+':'+rawStart.substring(11,13))
            if (!isNaN(s)) this.form.dtstart = toLocalISO(s)
          }
        }
        if (rawEnd) {
          const isAllDay = rawEnd.length === 8
          if (isAllDay) {
            this.form.dtend = `${rawEnd.substring(0,4)}-${rawEnd.substring(4,6)}-${rawEnd.substring(6,8)}`
          } else {
            const ed = new Date(rawEnd.substring(0,4)+'-'+rawEnd.substring(4,6)+'-'+rawEnd.substring(6,8)+'T'+rawEnd.substring(9,11)+':'+rawEnd.substring(11,13))
            if (!isNaN(ed)) this.form.dtend = toLocalISO(ed)
          }
        }
      } catch(e) {}
    }
  },
  methods: {
    async save() {
      this.saving = true
      try {
        let ds, de
        if (this.form.allDay) {
          ds = this.form.dtstart.replace(/-/g, '')
          de = this.form.dtend.replace(/-/g, '')
        } else {
          ds = this.form.dtstart.replace(/[-:]/g, '').replace('T', '') + '00'
          de = this.form.dtend.replace(/[-:]/g, '').replace('T', '') + '00'
        }

        if (this.isNew) {
          const ical = `BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//PersonalDAV\r\nBEGIN:VEVENT\r\nUID:${Date.now()}@personaldav\r\nDTSTART:${ds}\r\nDTEND:${de}\r\nSUMMARY:${this.form.summary}\r\n${this.form.categories ? 'CATEGORIES:'+this.form.categories+'\r\n' : ''}${this.form.location ? 'LOCATION:'+this.form.location+'\r\n' : ''}${this.form.description ? 'DESCRIPTION:'+this.form.description+'\r\n' : ''}END:VEVENT\r\nEND:VCALENDAR\r\n`
          await api.createEvent(ical)
        } else if (this._rawIcal) {
          const lines = this._rawIcal.split('\n').map(l => l.trim())
          setVeventField(lines, 'SUMMARY', this.form.summary)
          setVeventField(lines, 'DESCRIPTION', this.form.description)
          setVeventField(lines, 'CATEGORIES', this.form.categories)
          setVeventField(lines, 'LOCATION', this.form.location)
          setVeventField(lines, 'DTSTART', ds)
          setVeventField(lines, 'DTEND', de)
          await api.updateEvent(this.loadedUid, lines.join('\r\n'))
        } else {
          const ical = `BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//PersonalDAV\r\nBEGIN:VEVENT\r\nUID:${this.loadedUid}\r\nDTSTART:${ds}\r\nDTEND:${de}\r\nSUMMARY:${this.form.summary}\r\n${this.form.categories ? 'CATEGORIES:'+this.form.categories+'\r\n' : ''}${this.form.description ? 'DESCRIPTION:'+this.form.description+'\r\n' : ''}END:VEVENT\r\nEND:VCALENDAR\r\n`
          await api.updateEvent(this.loadedUid, ical)
        }
        this.$router.push('/calendar')
      } catch(e) { alert('保存失败: ' + (e.message || e)) } finally { this.saving = false }
    },
  },
}
</script>

<style scoped>
.form-card { background: var(--bg-card); border-radius: 8px; padding: 24px; max-width: 520px; box-shadow: var(--shadow-sm); }
.form-card h3 { margin: 0 0 20px; }
label { display: block; margin-bottom: 4px; font-size: 14px; color: var(--text-secondary); }
input, textarea { width: 100%; padding: 8px 12px; border: 1px solid var(--border-input); border-radius: 6px; font-size: 14px; box-sizing: border-box; margin-bottom: 16px; font-family: inherit; }
input[type="checkbox"] { width: auto; margin-right: 6px; }
.form-actions { display: flex; gap: 12px; margin-top: 8px; }
.btn-primary { padding: 8px 20px; background: var(--brand); color: var(--text-inverse); border: none; border-radius: 6px; font-size: 14px; cursor: pointer; }
.btn-cancel { padding: 8px 20px; background: var(--bg-card); color: var(--text-secondary); border: 1px solid var(--border-strong); border-radius: 6px; text-decoration: none; font-size: 14px; }
</style>
