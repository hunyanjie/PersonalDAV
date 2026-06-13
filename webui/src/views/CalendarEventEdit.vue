<template>
  <div class="edit-page">
    <div class="form-card glass">
      <div class="form-header">
        <h3>{{ isNew ? '新建日程事件' : '编辑日程事件' }}</h3>
        <p class="form-subtitle">管理您的个人日程并跨设备同步</p>
      </div>

      <form @submit.prevent="save">
        <div class="form-grid">
          <div class="form-item full" :class="{ focused: focusedField === 'summary' }">
            <label>日程标题</label>
            <input v-model="form.summary" required placeholder="例如：团队周会" @focus="focusedField='summary'" @blur="focusedField=null" />
            <span v-if="form.summary && form.summary.length < 2" class="field-error">标题至少 2 个字符</span>
          </div>

          <div class="form-item" :class="{ focused: focusedField === 'categories' }">
            <label>分类</label>
            <input v-model="form.categories" placeholder="MEETING, WORK (逗号分隔)" @focus="focusedField='categories'" @blur="focusedField=null" />
          </div>

          <div class="form-item" :class="{ focused: focusedField === 'location' }">
            <label>地点</label>
            <div class="input-with-icon">
              <MapPin :size="16" class="inner-icon" />
              <input v-model="form.location" placeholder="会议室或地理位置" @focus="focusedField='location'" @blur="focusedField=null" />
            </div>
          </div>

          <div class="form-item full checkbox-row">
            <label class="checkbox-label">
              <input type="checkbox" v-model="form.allDay" />
              <span>全天事件</span>
            </label>
          </div>

          <div class="form-item" :class="{ focused: focusedField === 'dtstart' }">
            <label>开始时间</label>
            <input v-model="form.dtstart" :type="form.allDay ? 'date' : 'datetime-local'" required @focus="focusedField='dtstart'" @blur="focusedField=null" />
          </div>

          <div class="form-item" :class="{ focused: focusedField === 'dtend' }">
            <label>结束时间</label>
            <input v-model="form.dtend" :type="form.allDay ? 'date' : 'datetime-local'" required @focus="focusedField='dtend'" @blur="focusedField=null" />
          </div>

          <div class="form-item full" :class="{ focused: focusedField === 'description' }">
            <label>日程描述</label>
            <textarea v-model="form.description" rows="4" placeholder="添加更多关于此日程的详细备注..." @focus="focusedField='description'" @blur="focusedField=null"></textarea>
          </div>
        </div>

        <div class="form-actions">
          <button type="submit" class="btn-primary" :disabled="saving">
            <Save :size="18" v-if="!saving" />
            <span v-else class="spinning-icon">⏳</span>
            {{ saving ? '正在保存...' : '保存日程' }}
          </button>
          <router-link to="/calendar" class="btn-cancel">取消</router-link>
        </div>
      </form>
    </div>
  </div>
</template>

<script>
import { Save, MapPin } from 'lucide-vue-next'
import api from '../api.js'

function toLocalISO(d) {
  if (!d) return ''
  const pad = n => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
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
  components: { Save, MapPin },
  data: () => ({
    form: { summary: '', description: '', categories: '', location: '', dtstart: '', dtend: '', allDay: false },
    saving: false, isNew: true, _rawIcal: '', loadedUid: '',
    focusedField: null,
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
      if (!this.form.summary || !this.form.dtstart || !this.form.dtend) return alert('请填写完整必填信息')
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
          const ical = `BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//PersonalDAV\r\nBEGIN:VEVENT\r\nUID:${this.loadedUid}\r\nDTSTART:${ds}\r\nDTEND:${de}\r\nSUMMARY:${this.form.summary}\r\n${this.form.categories ? 'CATEGORIES:'+this.form.categories+'\r\n' : ''}${this.form.location ? 'LOCATION:'+this.form.location+'\r\n' : ''}${this.form.description ? 'DESCRIPTION:'+this.form.description+'\r\n' : ''}END:VEVENT\r\nEND:VCALENDAR\r\n`
          await api.updateEvent(this.loadedUid, ical)
        }
        this.$router.push('/calendar')
      } catch(e) { alert('保存失败: ' + (e.message || e)) } finally { this.saving = false }
    },
  },
}
</script>

<style scoped>
.edit-page { display: flex; justify-content: center; padding-top: 20px; }

.form-card { 
  background: var(--bg-card); 
  border-radius: var(--radius-lg); 
  padding: 40px; 
  width: 100%;
  max-width: 680px; 
  box-shadow: var(--shadow-lg); 
  border: 1px solid var(--border-base);
}

.form-header { margin-bottom: 32px; border-bottom: 1px solid var(--border-base); padding-bottom: 20px; }
.form-header h3 { margin: 0 0 8px; font-size: 22px; color: var(--text-primary); }
.form-subtitle { margin: 0; color: var(--text-secondary); font-size: 14px; }

.form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
.form-item.full { grid-column: span 2; }

label { display: block; margin-bottom: 8px; font-size: 13px; font-weight: 700; color: var(--text-secondary); transition: color .2s; }
.form-item.focused label { color: var(--brand); }
.field-error { display: block; font-size: 12px; color: var(--danger); margin-top: 4px; }
input, textarea { 
  width: 100%; 
  padding: 12px 16px; 
  border: 1px solid var(--border-input); 
  border-radius: var(--radius-md); 
  font-size: 15px; 
  box-sizing: border-box; 
  background: #fafafa;
  font-family: inherit; 
  transition: all .2s;
}
input:focus, textarea:focus {
  border-color: var(--brand);
  background: white;
  box-shadow: 0 0 0 3px var(--brand-ring);
  outline: none;
}

.checkbox-row { margin-top: -12px; }
.checkbox-label { display: flex; align-items: center; gap: 10px; cursor: pointer; color: var(--text-primary) !important; font-weight: 500; }
.checkbox-label input { width: 18px; height: 18px; cursor: pointer; }

.input-with-icon { position: relative; }
.inner-icon { position: absolute; left: 12px; top: 50%; transform: translateY(-50%); color: var(--text-tertiary); }
.input-with-icon input { padding-left: 36px; }

.form-actions { display: flex; gap: 16px; margin-top: 40px; border-top: 1px solid var(--border-base); padding-top: 32px; }

.btn-primary { 
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 12px 28px; 
  background: var(--brand); 
  color: var(--text-inverse); 
  border: none; 
  border-radius: var(--radius-md); 
  font-size: 15px; 
  font-weight: 600;
  cursor: pointer; 
  transition: all .2s;
  box-shadow: 0 4px 12px hsla(var(--brand-hue) var(--brand-sat) var(--brand-lit) / 0.2);
}
.btn-primary:hover { background: var(--brand-hover); transform: translateY(-1px); box-shadow: 0 6px 16px hsla(var(--brand-hue) var(--brand-sat) var(--brand-lit) / 0.3); }
.btn-primary:disabled { opacity: 0.6; cursor: not-allowed; }

.btn-cancel { 
  padding: 12px 28px; 
  background: white; 
  color: var(--text-secondary); 
  border: 1px solid var(--border-strong); 
  border-radius: var(--radius-md); 
  text-decoration: none; 
  font-size: 15px; 
  font-weight: 600;
  transition: .2s;
}
.btn-cancel:hover { border-color: var(--text-primary); color: var(--text-primary); background: #fafafa; }

@media (max-width: 600px) {
  .form-grid { grid-template-columns: 1fr; }
  .form-card { padding: 24px; }
}
</style>
