<template>
  <div class="form-card">
    <h3>{{ isNew ? '新建事件' : '编辑事件' }}</h3>
    <form @submit.prevent="save">
      <label>标题</label>
      <input v-model="form.summary" required />
      <label>开始时间</label>
      <input v-model="form.dtstart" type="datetime-local" required />
      <label>结束时间</label>
      <input v-model="form.dtend" type="datetime-local" required />
      <label>描述</label>
      <textarea v-model="form.description" rows="3"></textarea>
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

function makeIcal(data) {
  const ds = data.dtstart.replace('T', '') + '00'
  const de = data.dtend.replace('T', '') + '00'
  return `BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//PersonalDAV\r\nBEGIN:VEVENT\r\nUID:${Date.now()}@personaldav\r\nDTSTART:${ds}\r\nDTEND:${de}\r\nSUMMARY:${data.summary}\r\n${data.description ? 'DESCRIPTION:'+data.description+'\r\n' : ''}END:VEVENT\r\nEND:VCALENDAR\r\n`
}

export default {
  data: () => ({
    form: { summary: '', dtstart: '', dtend: '', description: '' },
    saving: false, isNew: true, loadedUid: null,
  }),
  async mounted() {
    const uid = this.$route.params.uid
    if (uid) {
      this.isNew = false; this.loadedUid = uid
      try {
        const e = await api.getEvent(uid)
        this.form.summary = e.summary || ''
        this.form.description = e.description || ''
        if (e.dtstart) {
          const s = new Date(e.dtstart)
          if (!isNaN(s)) this.form.dtstart = toLocalISO(s)
        }
        if (e.dtend) {
          const ed = new Date(e.dtend)
          if (!isNaN(ed)) this.form.dtend = toLocalISO(ed)
        }
      } catch(e) {}
    }
  },
  methods: {
    async save() {
      this.saving = true
      try {
        const ical = makeIcal(this.form)
        if (this.isNew) {
          await api.createEvent(ical)
        } else {
          await api.updateEvent(this.loadedUid, ical)
        }
        this.$router.push('/calendar')
      } catch(e) { alert('保存失败') } finally { this.saving = false }
    },
  },
}
</script>

<style scoped>
.form-card { background: #fff; border-radius: 8px; padding: 24px; max-width: 480px; box-shadow: 0 1px 4px rgba(0,0,0,.06); }
.form-card h3 { margin: 0 0 20px; }
label { display: block; margin-bottom: 4px; font-size: 14px; color: #555; }
input, textarea { width: 100%; padding: 8px 12px; border: 1px solid #d9d9d9; border-radius: 6px; font-size: 14px; box-sizing: border-box; margin-bottom: 16px; font-family: inherit; }
.form-actions { display: flex; gap: 12px; margin-top: 8px; }
.btn-primary { padding: 8px 20px; background: #1677ff; color: #fff; border: none; border-radius: 6px; font-size: 14px; cursor: pointer; }
.btn-cancel { padding: 8px 20px; background: #fff; color: #555; border: 1px solid #d9d9d9; border-radius: 6px; text-decoration: none; font-size: 14px; }
</style>
