<template>
  <div class="edit-page">
    <div class="form-card glass">
      <div class="form-header">
        <h3>{{ isNew ? '新建联系人' : '编辑联系人' }}</h3>
        <p class="form-subtitle">填写联系人详细信息并同步到云端</p>
      </div>
      
      <form @submit.prevent="save">
        <div class="form-grid">
          <div class="form-item full" :class="{ focused: focusedField === 'name' }">
            <label>姓名</label>
            <input v-model="form.full_name" required placeholder="例如：张三" @focus="focusedField='name'" @blur="focusedField=null" />
            <span v-if="form.full_name && form.full_name.length < 2" class="field-error">姓名至少 2 个字符</span>
          </div>
          <div class="form-item" :class="{ focused: focusedField === 'email' }">
            <label>邮箱</label>
            <input v-model="form.email" type="email" placeholder="example@mail.com" @focus="focusedField='email'" @blur="focusedField=null" />
            <span v-if="form.email && !isValidEmail" class="field-error">邮箱格式不正确</span>
          </div>
          <div class="form-item" :class="{ focused: focusedField === 'phone' }">
            <label>电话</label>
            <input v-model="form.phone" placeholder="手机或座机号码" @focus="focusedField='phone'" @blur="focusedField=null" />
          </div>
          <div class="form-item" :class="{ focused: focusedField === 'groups' }">
            <label>分组</label>
            <input v-model="form.groups" placeholder="朋友;同事;家人 (分号分隔)" @focus="focusedField='groups'" @blur="focusedField=null" />
          </div>
          <div class="form-item" :class="{ focused: focusedField === 'org' }">
            <label>组织</label>
            <input v-model="form.org" placeholder="公司或学校名称" @focus="focusedField='org'" @blur="focusedField=null" />
          </div>
          <div class="form-item full" :class="{ focused: focusedField === 'address' }">
            <label>地址</label>
            <input v-model="form.address" placeholder="详细居住或办公地址" @focus="focusedField='address'" @blur="focusedField=null" />
          </div>
          <div class="form-item full" :class="{ focused: focusedField === 'note' }">
            <label>备注</label>
            <textarea v-model="form.note" rows="3" placeholder="添加一些额外的信息..." @focus="focusedField='note'" @blur="focusedField=null"></textarea>
          </div>
        </div>

        <div class="form-actions">
          <button type="submit" class="btn-primary" :disabled="saving">
            <Save :size="18" v-if="!saving" />
            <span v-else class="spinning-icon">⏳</span>
            {{ saving ? '正在保存...' : '保存联系人' }}
          </button>
          <router-link to="/contacts" class="btn-cancel">取消</router-link>
        </div>
      </form>
    </div>
  </div>
</template>

<script>
import { Save } from 'lucide-vue-next'
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
  components: { Save },
  data: () => ({
    form: { full_name: '', email: '', phone: '', groups: '', address: '', org: '', note: '' },
    saving: false, isNew: true, _rawVcard: '',
    focusedField: null,
  }),
  computed: {
    isValidEmail() {
      return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(this.form.email)
    },
  },
  async mounted() {
    const uid = this.$route.params.uid
    if (uid) {
      this.isNew = false
      try {
        const res = await api.getContact(uid)
        this._rawVcard = res.vcard || ''
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
      if (!this.form.full_name) return showToast('姓名不能为空', 'warning')
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
      } catch(e) { showToast('保存失败: ' + (e.message || e), 'error') } finally { this.saving = false }
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
