<template>
  <div class="edit-page">
    <div class="form-card glass">
      <div class="form-header">
        <h3>{{ isNew ? '新建日程事件' : '编辑日程事件' }}</h3>
        <p class="form-subtitle">管理您的个人日程并跨设备同步</p>
      </div>

      <form @submit.prevent="save" @dragover.prevent @drop.prevent="onFileDrop">
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

        <!-- Reminders -->
        <div class="section-block">
          <h4 class="section-title">提醒</h4>
          <div v-for="(r, i) in form.reminders" :key="i" class="reminder-chip">
            <span class="reminder-text">{{ r.action }} · {{ r.triggerDesc }}</span>
            <button type="button" class="chip-btn" @click="editReminder(i)"><Pencil :size="14" /></button>
            <button type="button" class="chip-btn" @click="form.reminders.splice(i,1)"><X :size="14" /></button>
          </div>
          <div v-if="reminderForm" class="reminder-form glass">
            <div class="rf-row">
              <label>动作</label>
              <select v-model="reminderForm.action">
                <option>AUDIO</option><option>DISPLAY</option><option>EMAIL</option>
              </select>
            </div>
            <div class="rf-row">
              <label>触发</label>
              <select v-model="reminderForm.triggerType" style="width:80px;">
                <option value="before">之前</option><option value="after">之后</option>
              </select>
              <input v-model.number="reminderForm.triggerValue" type="number" min="1" style="width:60px;" />
              <select v-model="reminderForm.triggerUnit" style="width:80px;">
                <option value="M">分钟</option><option value="H">小时</option><option value="D">天</option>
              </select>
            </div>
            <div class="rf-actions">
              <button type="button" class="btn-sm" @click="reminderForm=null; editingReminderIdx=-1">取消</button>
              <button type="button" class="btn-sm btn-primary" @click="confirmReminder">{{ editingReminderIdx>=0 ? '修改' : '添加' }}</button>
            </div>
          </div>
          <button v-else type="button" class="btn-sm" @click="addReminder" style="margin-top:8px;">+ 添加提醒</button>
        </div>

        <!-- Repeat -->
        <div class="section-block">
          <h4 class="section-title">重复规则</h4>
          <div class="rf-row">
            <select v-model="form.repeatType" @change="onRepeatChange" style="min-width:100px;">
              <option>不重复</option><option>每日</option><option>每周</option><option>每月</option><option>每年</option>
            </select>
            <template v-if="form.repeatType !== '不重复'">
              <label style="margin:0 8px;">每</label>
              <input v-model.number="form.repeatInterval" type="number" min="1" style="width:50px;" />
              <label>{{ form.repeatType === '每日' ? '天' : form.repeatType === '每周' ? '周' : form.repeatType === '每月' ? '个月' : '年' }}</label>
              <select v-if="form.repeatType==='每周'" v-model="form.repeatByDay" style="width:72px; margin-left:8px;">
                <option>MO</option><option>TU</option><option>WE</option><option>TH</option><option>FR</option><option>SA</option><option>SU</option>
              </select>
              <input v-if="form.repeatType==='每月'" v-model.number="form.repeatByMonthDay" type="number" min="1" max="31" style="width:50px; margin-left:8px;" />
            </template>
          </div>
          <div v-if="form.repeatType !== '不重复'" class="rf-row" style="margin-top:8px;">
            <label>结束</label>
            <select v-model="form.repeatEnd" style="width:100px;">
              <option>永不结束</option><option>次数</option><option>日期</option>
            </select>
            <template v-if="form.repeatEnd==='次数'">
              <input v-model.number="form.repeatCount" type="number" min="1" style="width:50px; margin-left:8px;" />
              <label style="margin-left:4px;">次后</label>
            </template>
            <input v-if="form.repeatEnd==='日期'" v-model="form.repeatUntil" type="date" style="margin-left:8px; width:140px;" />
          </div>
        </div>

        <!-- Attachments -->
        <div class="section-block">
          <h4 class="section-title">附件</h4>
          <div v-for="(a, i) in form.attachments" :key="i" class="reminder-chip">
            <span class="reminder-text">{{ a.name || a.url }}</span>
            <button type="button" class="chip-btn" @click="form.attachments.splice(i,1)"><X :size="14" /></button>
          </div>
          <div style="margin-top:8px; display:flex; gap:8px;">
            <button type="button" class="btn-sm" @click="addAttachment('file')">+ 添加文件</button>
            <button type="button" class="btn-sm" @click="addAttachment('url')">+ 添加链接</button>
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
      <div v-if="dragging" class="drop-overlay"><svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--brand)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg><span>松开以上传文件作为附件</span></div>

      <!-- URL 输入弹窗 -->
      <transition name="modal">
        <div v-if="showUrlDialog" class="modal-overlay" @click.self="cancelUrl">
          <div class="modal-card" style="max-width:420px;">
            <div class="modal-header"><h3>添加链接附件</h3><button type="button" class="btn-close-circle" @click="cancelUrl"><X :size="20" /></button></div>
            <div class="modal-body">
              <div class="form-group">
                <label>链接地址</label>
                <input v-model="urlInput" placeholder="https://example.com/file.pdf" @keyup.enter="confirmUrl" autofocus />
              </div>
            </div>
            <div class="modal-footer">
              <button type="button" class="btn-cancel" @click="cancelUrl" style="padding:8px 24px;">取消</button>
              <button type="button" class="btn-primary" @click="confirmUrl" :disabled="!urlInput.trim()" style="padding:8px 24px;border:none;">确认</button>
            </div>
          </div>
        </div>
      </transition>
    </div>
  </div>
</template>

<script>
import { Save, MapPin, Pencil, X } from 'lucide-vue-next'
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
  components: { Save, MapPin, Pencil, X },
  data: () => ({
    form: { summary: '', description: '', categories: '', location: '', dtstart: '', dtend: '', allDay: false,
      reminders: [], repeatType: '不重复', repeatInterval: 1, repeatByDay: 'MO', repeatByMonthDay: 1,
      repeatEnd: '永不结束', repeatCount: 5, attachments: [] },
    saving: false, isNew: true, _rawIcal: '', loadedUid: '',
    focusedField: null,
    reminderForm: null,
    editingReminderIdx: -1,
    showUrlDialog: false,
    urlInput: '',
    dragging: false,
    _dragCount: 0,
  }),
  async mounted() {
    const uid = this.$route.params.uid
    if (uid) {
      this.isNew = false; this.loadedUid = uid
      try {
        const e = await api.getEvent(uid)
        this._rawIcal = e.ical || ''
        
        // 更鲁棒的解析逻辑
        const lines = this._rawIcal.split(/\r?\n/)
        this.form.summary = getField(lines, 'SUMMARY')
        this.form.description = getField(lines, 'DESCRIPTION')
        this.form.categories = getField(lines, 'CATEGORIES')
        this.form.location = getField(lines, 'LOCATION')

        const rawStart = getField(lines, 'DTSTART')
        const rawEnd = getField(lines, 'DTEND')
        if (rawStart) {
          this.form.allDay = rawStart.length <= 8
          if (this.form.allDay) this.form.dtstart = `${rawStart.substring(0,4)}-${rawStart.substring(4,6)}-${rawStart.substring(6,8)}`
          else {
            const s = new Date(rawStart.substring(0,4)+'-'+rawStart.substring(4,6)+'-'+rawStart.substring(6,8)+'T'+rawStart.substring(9,11)+':'+rawStart.substring(11,13))
            if (!isNaN(s)) this.form.dtstart = toLocalISO(s)
          }
        }
        if (rawEnd) {
          if (this.form.allDay) this.form.dtend = `${rawEnd.substring(0,4)}-${rawEnd.substring(4,6)}-${rawEnd.substring(6,8)}`
          else {
            const ed = new Date(rawEnd.substring(0,4)+'-'+rawEnd.substring(4,6)+'-'+rawEnd.substring(6,8)+'T'+rawEnd.substring(9,11)+':'+rawEnd.substring(11,13))
            if (!isNaN(ed)) this.form.dtend = toLocalISO(ed)
          }
        }

        // 解析提醒 (VALARM)
        this.form.reminders = []
        let inAlarm = false, currentAlarm = {}
        for (const line of lines) {
          const u = line.toUpperCase()
          if (u.startsWith('BEGIN:VALARM')) { inAlarm = true; currentAlarm = {} }
          else if (u.startsWith('END:VALARM')) {
            if (currentAlarm.trigger) {
              let trig = currentAlarm.trigger, triggerType = 'before', triggerValue = 15, triggerUnit = 'M'
              if (trig.startsWith('-P')) {
                const m = trig.match(/-P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?)?/)
                if (m) {
                  const d = parseInt(m[1]||'0'), h = parseInt(m[2]||'0'), min = parseInt(m[3]||'0')
                  triggerValue = d * 1440 + h * 60 + min
                  if (d > 0 && h === 0 && min === 0) triggerUnit = 'D'
                  else if (h > 0 && min === 0) triggerUnit = 'H'
                  else triggerUnit = 'M'
                }
              } else if (trig.startsWith('PT')) {
                triggerType = 'after'
                const m = trig.match(/PT(?:(\d+)H)?(?:(\d+)M)?/)
                if (m) triggerValue = parseInt(m[1]||'0')*60 + parseInt(m[2]||'0')
              }
              this.form.reminders.push({
                action: currentAlarm.action || 'DISPLAY',
                triggerType, triggerValue, triggerUnit,
                triggerDesc: (triggerType === 'before' ? '提前' : '延后') + triggerValue + '分钟'
              })
            }
            inAlarm = false
          } else if (inAlarm) {
            if (u.startsWith('ACTION:')) currentAlarm.action = line.split(':')[1].trim()
            if (u.startsWith('TRIGGER:')) currentAlarm.trigger = line.split(':')[1].trim()
          }
        }

        // 解析重复规则 (RRULE)
        const rrule = getField(lines, 'RRULE')
        if (rrule) {
          const parts = {}
          rrule.split(';').forEach(p => { const [k,v] = p.split('='); parts[k.toUpperCase()] = v })
          if (parts.FREQ === 'DAILY') this.form.repeatType = '每日'
          else if (parts.FREQ === 'WEEKLY') { this.form.repeatType = '每周'; this.form.repeatByDay = (parts.BYDAY||'MO').split(',')[0] }
          else if (parts.FREQ === 'MONTHLY') { this.form.repeatType = '每月'; this.form.repeatByMonthDay = parseInt(parts.BYMONTHDAY||'1') }
          else if (parts.FREQ === 'YEARLY') this.form.repeatType = '每年'
          this.form.repeatInterval = parseInt(parts.INTERVAL || '1')
          if (parts.COUNT) { this.form.repeatEnd = '次数'; this.form.repeatCount = parseInt(parts.COUNT) }
          else if (parts.UNTIL) {
            const u = parts.UNTIL; this.form.repeatEnd = '日期'; 
            this.form.repeatUntil = `${u.substring(0,4)}-${u.substring(4,6)}-${u.substring(6,8)}`
          }
        }

        // 解析附件 (ATTACH)
        this.form.attachments = []
        // 先处理折行 (iCalendar 规范中折行以空格开头)
        const unfoldedLines = []
        for (let i = 0; i < lines.length; i++) {
          if (i > 0 && lines[i].startsWith(' ')) {
            unfoldedLines[unfoldedLines.length - 1] += lines[i].substring(1)
          } else {
            unfoldedLines.push(lines[i])
          }
        }
        for (const line of unfoldedLines) {
          if (line.toUpperCase().includes('ATTACH')) {
            const parts = line.split(':'), head = parts[0], val = parts.slice(1).join(':')
            let fileName = '附件'
            
            // 尝试从参数中获取文件名
            const nameMatch = head.match(/FILENAME=([^;]+)/i)
            if (nameMatch) {
              fileName = decodeURIComponent(nameMatch[1].trim())
            } else {
              // 降级使用路径或 URL 的最后部分
              fileName = val.split('/').pop().split('\\').pop() || '附件'
              fileName = decodeURIComponent(fileName)
            }

            if (head.toUpperCase().includes('ENCODING=BASE64')) {
              const typeMatch = head.match(/FMTTYPE=(.*?)(;|$)/i)
              const mime = typeMatch ? typeMatch[1] : 'application/octet-stream'
              this.form.attachments.push({ name: fileName, url: `data:${mime};base64,${val}` })
            } else {
              this.form.attachments.push({ name: fileName, url: val })
            }
          }
        }
      } catch(e) { console.error('加载失败', e) }
    }

    // 拖拽监听
    document.addEventListener('dragenter', this._onGlobalDragEnter)
    document.addEventListener('dragleave', this._onGlobalDragLeave)
    document.addEventListener('drop', this._onGlobalDrop)
  },
  beforeUnmount() {
    document.removeEventListener('dragenter', this._onGlobalDragEnter)
    document.removeEventListener('dragleave', this._onGlobalDragLeave)
    document.removeEventListener('drop', this._onGlobalDrop)
  },
  methods: {
    _buildIcal(ds, de, uid) {
      let lines = `BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//PersonalDAV\r\nBEGIN:VEVENT\r\nUID:${uid}\r\nDTSTART:${ds}\r\nDTEND:${de}\r\n`
      if (this.isNew) lines += 'STATUS:CONFIRMED\r\n'
      lines += `SUMMARY:${this.form.summary}\r\n`
      if (this.form.categories) lines += `CATEGORIES:${this.form.categories}\r\n`
      if (this.form.location) lines += `LOCATION:${this.form.location}\r\n`
      if (this.form.description) lines += `DESCRIPTION:${this.form.description}\r\n`

      if (this.form.repeatType !== '不重复') {
        const freqMap = { '每日':'DAILY','每周':'WEEKLY','每月':'MONTHLY','每年':'YEARLY' }
        let rr = `RRULE:FREQ=${freqMap[this.form.repeatType]};INTERVAL=${this.form.repeatInterval}`
        if (this.form.repeatType === '每周') rr += `;BYDAY=${this.form.repeatByDay}`
        if (this.form.repeatType === '每月') rr += `;BYMONTHDAY=${this.form.repeatByMonthDay}`
        if (this.form.repeatEnd === '次数') rr += `;COUNT=${this.form.repeatCount}`
        else if (this.form.repeatEnd === '日期' && this.form.repeatUntil) rr += `;UNTIL=${this.form.repeatUntil.replace(/-/g,'')}T235959Z`
        lines += rr + '\r\n'
      }

      for (const r of this.form.reminders) {
        let trig
        if (r.triggerType === 'after') trig = `PT${r.triggerValue}M`
        else {
          const d = Math.floor(r.triggerValue / 1440), h = Math.floor((r.triggerValue % 1440) / 60), m = r.triggerValue % 60
          trig = '-P' + (d ? d+'D' : '') + (h||m ? 'T' : '') + (h ? h+'H' : '') + (m ? m+'M' : '')
          if (!d && !h && !m) trig = '-PT0M'
        }
        lines += `BEGIN:VALARM\r\nACTION:${r.action}\r\nTRIGGER:${trig}\r\nEND:VALARM\r\n`
      }

      for (const a of this.form.attachments) {
        if (a.url.startsWith('data:')) {
          const [meta, b64] = a.url.split(','), mime = meta.match(/:(.*?);/)?.[1] || 'application/octet-stream'
          lines += `ATTACH;VALUE=BINARY;ENCODING=BASE64;FMTTYPE=${mime};FILENAME=${a.name}:${b64}\r\n`
        } else if (a.url) {
          lines += `ATTACH:${a.url}\r\n`
        }
      }

      lines += 'END:VEVENT\r\nEND:VCALENDAR\r\n'
      return lines
    },

    async save() {
      if (!this.form.summary || !this.form.dtstart || !this.form.dtend) return window.showToast('请填写完整必填信息', 'warning')
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
          await api.createEvent(this._buildIcal(ds, de, Date.now() + '@personaldav'))
          window.showToast('日程创建成功', 'success')
        } else if (this._rawIcal) {
          const allIcal = this._buildIcal(ds, de, this.loadedUid)
          await api.updateEvent(this.loadedUid, allIcal)
          window.showToast('日程已更新', 'success')
        } else {
          await api.updateEvent(this.loadedUid, this._buildIcal(ds, de, this.loadedUid))
          window.showToast('日程已更新', 'success')
        }
        this.$router.push('/calendar')
      } catch(e) { window.showToast('保存失败: ' + (e.message || e), 'error') } finally { this.saving = false }
    },

    addReminder() {
      this.reminderForm = { action: 'DISPLAY', triggerType: 'before', triggerValue: 15, triggerUnit: 'M' }
      this.editingReminderIdx = -1
    },
    editReminder(idx) {
      const r = this.form.reminders[idx]
      this.reminderForm = { action: r.action, triggerType: r.triggerType, triggerValue: r.triggerValue, triggerUnit: r.triggerUnit }
      this.editingReminderIdx = idx
    },
    confirmReminder() {
      const rf = this.reminderForm
      const totalMin = rf.triggerUnit === 'D' ? rf.triggerValue * 1440 : rf.triggerUnit === 'H' ? rf.triggerValue * 60 : rf.triggerValue
      const trigDesc = rf.triggerType === 'before' ? `提前${totalMin}分钟` : `延后${totalMin}分钟`
      const entry = { action: rf.action, triggerDesc: trigDesc, triggerType: rf.triggerType, triggerValue: totalMin, triggerUnit: rf.triggerUnit }
      if (this.editingReminderIdx >= 0) {
        this.form.reminders[this.editingReminderIdx] = entry
      } else {
        this.form.reminders.push(entry)
      }
      this.reminderForm = null
      this.editingReminderIdx = -1
    },
    onRepeatChange() {
      if (this.form.repeatType === '不重复') {
        this.form.repeatInterval = 1
      }
    },
    addAttachment(type) {
      if (type === 'file') {
        this._pickFile()
      } else {
        this.showUrlDialog = true
        this.urlInput = ''
      }
    },
    addFilesAsAttachments(files) {
      for (const file of files) {
        const reader = new FileReader()
        reader.onload = (e) => {
          this.form.attachments.push({ url: e.target.result, name: file.name })
        }
        reader.readAsDataURL(file)
      }
    },
    _pickFile() {
      const input = document.createElement('input')
      input.type = 'file'
      input.onchange = () => {
        if (input.files[0]) {
          const reader = new FileReader()
          reader.onload = (e) => {
            this.form.attachments.push({ url: e.target.result, name: input.files[0].name })
          }
          reader.readAsDataURL(input.files[0])
        }
      }
      input.click()
    },
    onFileDrop(e) {
      this.dragging = false
      this._dragCount = 0
      const files = e.dataTransfer.files
      if (files.length) this.addFilesAsAttachments(files)
    },
    escapeIcal(str) {
      if (!str) return '';
      return String(str)
        .replace(/\\/g, '\\\\')
        .replace(/;/g, '\\;')
        .replace(/,/g, '\\,')
        .replace(/\n/g, '\\n');
    },
    openUrlDialog() {
      this.showUrlDialog = true
      this.urlInput = ''
    },
    confirmUrl() {
      const url = this.urlInput.trim()
      if (url) {
        this.form.attachments.push({ url, name: url.split('/').pop() || '链接' })
        this.showUrlDialog = false
        this.urlInput = ''
      }
    },
    cancelUrl() {
      this.showUrlDialog = false
      this.urlInput = ''
    },
    _onGlobalDragEnter(e) {
      if (e.dataTransfer.types?.includes('Files')) {
        this._dragCount++
        this.dragging = true
      }
    },
    _onGlobalDragLeave() {
      this._dragCount--
      if (this._dragCount <= 0) { this._dragCount = 0; this.dragging = false }
    },
    _onGlobalDrop(e) {
      this._dragCount = 0
      this.dragging = false
      if (e.dataTransfer.files?.length) {
        e.preventDefault()
        this.addFilesAsAttachments(e.dataTransfer.files)
      }
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

.section-block { margin-top: 28px; border-top: 1px solid var(--border-base); padding-top: 20px; }
.section-title { font-size: 15px; font-weight: 700; margin: 0 0 12px; display: flex; align-items: center; gap: 8px; color: var(--text-primary); }
.reminder-chip { display: inline-flex; align-items: center; gap: 6px; background: var(--bg-hover); border-radius: var(--radius-md); padding: 4px 10px; margin: 4px 6px 4px 0; font-size: 13px; }
.chip-btn { background: none; border: none; cursor: pointer; color: var(--text-tertiary); padding: 2px; display: inline-flex; transition: color .15s; }
.chip-btn:hover { color: var(--text-primary); }
.reminder-form { background: var(--bg-card); border: 1px solid var(--border-base); border-radius: var(--radius-md); padding: 20px; margin-top: 12px; box-shadow: var(--shadow-md); display: flex; flex-direction: column; gap: 16px; }
.rf-row { display: flex; align-items: center; gap: 12px; }
.rf-row label { margin-bottom: 0; white-space: nowrap; min-width: 40px; }
.rf-row select, .rf-row input { 
  padding: 8px 12px; border: 1px solid var(--border-input); border-radius: 6px; 
  background: #fafafa; font-size: 14px; transition: all .2s; outline: none;
}
.rf-row select:focus, .rf-row input:focus { border-color: var(--brand); background: white; box-shadow: 0 0 0 3px var(--brand-ring); }
.rf-actions { display: flex; gap: 12px; justify-content: flex-end; margin-top: 4px; border-top: 1px solid var(--border-base); padding-top: 16px; }

.section-block select { padding: 8px 12px; border: 1px solid var(--border-input); border-radius: 6px; background: #fafafa; font-size: 14px; transition: .2s; }
.section-block select:focus { border-color: var(--brand); background: white; }

.attachment-row { display: flex; align-items: center; gap: 10px; margin-top: 8px; }

.drop-overlay { position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.4); display:flex; flex-direction:column; align-items:center; justify-content:center; z-index:9999; gap:16px; backdrop-filter:blur(4px); }
.drop-overlay span { font-size:18px; font-weight:600; color:var(--brand); }

.modal-overlay { position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.4); display:flex; align-items:center; justify-content:center; z-index:5000; backdrop-filter:blur(8px); }
.modal-card { background:white; border-radius:var(--radius-xl); width:100%; max-width:500px; max-height:90vh; overflow-y:auto; box-shadow:var(--shadow-xl); border:1px solid var(--glass-border); }
.modal-header { padding:24px 32px; border-bottom:1px solid var(--border-base); display:flex; justify-content:space-between; align-items:center; position:relative; }
.modal-header h3 { margin:0; font-size:18px; font-weight:700; color:var(--text-primary); }
.modal-body { padding:24px 32px; display:flex; flex-direction:column; gap:16px; }
.modal-footer { padding:20px 32px; border-top:1px solid var(--border-base); display:flex; gap:12px; justify-content:flex-end; }
.btn-close-circle { background:transparent; border:none; padding:4px; color:var(--text-tertiary); cursor:pointer; transition:.2s; display:flex; }
.btn-close-circle:hover { color:var(--text-primary); transform:rotate(90deg); }
.form-group { display:flex; flex-direction:column; gap:6px; }
.form-group label { font-size:13px; font-weight:600; color:var(--text-secondary); }
.form-group input { padding:10px 12px; border:1px solid var(--border-input); border-radius:var(--radius-md); font-size:14px; background:#fafafa; transition:all .2s; outline:none; }
.form-group input:focus { border-color:var(--brand); background:white; box-shadow:0 0 0 3px var(--brand-ring); }
.btn-primary { padding:8px 24px; background:var(--brand); color:white; border:none; border-radius:var(--radius-md); font-size:14px; font-weight:600; cursor:pointer; transition:all .2s; }
.btn-primary:hover { filter:brightness(1.1); }
.btn-primary:disabled { opacity:0.5; cursor:not-allowed; }
</style>
