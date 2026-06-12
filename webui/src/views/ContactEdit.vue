<template>
  <div class="form-card">
    <h3>{{ isNew ? '新建联系人' : '编辑联系人' }}</h3>
    <form @submit.prevent="save">
      <label>姓名</label>
      <input v-model="form.full_name" required />
      <label>邮箱</label>
      <input v-model="form.email" type="email" />
      <label>电话</label>
      <input v-model="form.phone" />
      <label>分组（分号分隔）</label>
      <input v-model="form.groups" placeholder="朋友;同事;家人" />
      <label>地址</label>
      <input v-model="form.address" />
      <label>组织</label>
      <input v-model="form.org" />
      <label>备注</label>
      <textarea v-model="form.note" rows="3"></textarea>
      <div class="form-actions">
        <button type="submit" class="btn-primary" :disabled="saving">{{ saving ? '保存中...' : '保存' }}</button>
        <router-link to="/contacts" class="btn-cancel">取消</router-link>
      </div>
    </form>
  </div>
</template>

<script>
import api from '../api.js'

function getField(lines, key) {
  for (const l of lines) {
    if (l.toUpperCase().startsWith(key + ':') || l.toUpperCase().startsWith(key + ';'))
      return l.split(':', 1)[0] === l.split(':')[0] ? l.substring(l.indexOf(':') + 1).trim() : l.split(':').slice(1).join(':').trim()
  }
  return ''
}

function setField(lines, key, value) {
  const ukey = key.toUpperCase()
  let found = false
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].toUpperCase().startsWith(ukey + ':') || lines[i].toUpperCase().startsWith(ukey + ';')) {
      if (value) lines[i] = key + ':' + value
      else lines.splice(i, 1)
      found = true; break
    }
  }
  if (value && !found) {
    const ins = lines.findIndex(l => l.toUpperCase() === 'END:VCARD')
    if (ins >= 0) lines.splice(ins, 0, key + ':' + value)
    else lines.push(key + ':' + value)
  }
}

function buildVCard(form) {
  return `BEGIN:VCARD\r\nVERSION:3.0\r\nFN:${form.full_name}\r\nN:${form.full_name};;;\r\n${form.email ? 'EMAIL:'+form.email+'\r\n' : ''}${form.phone ? 'TEL:'+form.phone+'\r\n' : ''}${form.groups ? 'CATEGORIES:'+form.groups+'\r\n' : ''}${form.address ? 'ADR:'+form.address+'\r\n' : ''}${form.org ? 'ORG:'+form.org+'\r\n' : ''}${form.note ? 'NOTE:'+form.note+'\r\n' : ''}END:VCARD\r\n`
}

export default {
  data: () => ({
    form: { full_name: '', email: '', phone: '', groups: '', address: '', org: '', note: '' },
    saving: false, isNew: true, _rawVcard: '',
  }),
  async mounted() {
    const uid = this.$route.params.uid
    if (uid) {
      this.isNew = false
      try {
        const c = await api.getContact(uid)
        this._rawVcard = c.vcard || ''
        const lines = this._rawVcard.split('\n')
        this.form = {
          full_name: getField(lines, 'FN'),
          email: getField(lines, 'EMAIL'),
          phone: getField(lines, 'TEL'),
          groups: getField(lines, 'CATEGORIES'),
          address: getField(lines, 'ADR'),
          org: getField(lines, 'ORG'),
          note: getField(lines, 'NOTE'),
        }
      } catch(e) {}
    }
  },
  methods: {
    async save() {
      this.saving = true
      try {
        if (this.isNew) {
          await api.createContactStructured({
            full_name: this.form.full_name,
            email: this.form.email,
            phone: this.form.phone,
            groups: this.form.groups,
            address: this.form.address,
            org: this.form.org,
            note: this.form.note,
          })
        } else if (this._rawVcard) {
          const lines = this._rawVcard.split('\n').map(l => l.trim())
          setField(lines, 'FN', this.form.full_name)
          setField(lines, 'N', this.form.full_name + ';;;')
          setField(lines, 'EMAIL', this.form.email)
          setField(lines, 'TEL', this.form.phone)
          setField(lines, 'CATEGORIES', this.form.groups)
          setField(lines, 'ADR', this.form.address)
          setField(lines, 'ORG', this.form.org)
          setField(lines, 'NOTE', this.form.note)
          await api.updateContact(this.$route.params.uid, lines.join('\r\n'))
        } else {
          await api.updateContact(this.$route.params.uid, buildVCard(this.form))
        }
        this.$router.push('/contacts')
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
.form-actions { display: flex; gap: 12px; margin-top: 8px; }
.btn-primary { padding: 8px 20px; background: var(--brand); color: var(--text-inverse); border: none; border-radius: 6px; font-size: 14px; cursor: pointer; }
.btn-cancel { padding: 8px 20px; background: var(--bg-card); color: var(--text-secondary); border: 1px solid var(--border-strong); border-radius: 6px; text-decoration: none; font-size: 14px; }
</style>
