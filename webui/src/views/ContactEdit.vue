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
      <div class="form-actions">
        <button type="submit" class="btn-primary" :disabled="saving">{{ saving ? '保存中...' : '保存' }}</button>
        <router-link to="/contacts" class="btn-cancel">取消</router-link>
      </div>
    </form>
  </div>
</template>

<script>
import api from '../api.js'
export default {
  data: () => ({ form: { full_name: '', email: '', phone: '' }, saving: false, isNew: true }),
  async mounted() {
    const uid = this.$route.params.uid
    if (uid) {
      this.isNew = false
      try {
        const c = await api.getContact(uid)
        this.form = { full_name: c.full_name, email: c.email, phone: c.phone }
      } catch(e) {}
    }
  },
  methods: {
    async save() {
      this.saving = true
      try {
        if (this.isNew) {
          await api.createContactStructured(this.form)
        } else {
          const vcard = `BEGIN:VCARD\r\nVERSION:3.0\r\nFN:${this.form.full_name}\r\nN:${this.form.full_name};;;\r\n${this.form.email ? 'EMAIL:'+this.form.email+'\r\n' : ''}${this.form.phone ? 'TEL:'+this.form.phone+'\r\n' : ''}END:VCARD\r\n`
          await api.updateContact(this.$route.params.uid, vcard)
        }
        this.$router.push('/contacts')
      } catch(e) { alert('保存失败') } finally { this.saving = false }
    },
  },
}
</script>

<style scoped>
.form-card { background: #fff; border-radius: 8px; padding: 24px; max-width: 480px; box-shadow: 0 1px 4px rgba(0,0,0,.06); }
.form-card h3 { margin: 0 0 20px; }
label { display: block; margin-bottom: 4px; font-size: 14px; color: #555; }
input { width: 100%; padding: 8px 12px; border: 1px solid #d9d9d9; border-radius: 6px; font-size: 14px; box-sizing: border-box; margin-bottom: 16px; }
.form-actions { display: flex; gap: 12px; margin-top: 8px; }
.btn-primary { padding: 8px 20px; background: #1677ff; color: #fff; border: none; border-radius: 6px; font-size: 14px; cursor: pointer; }
.btn-cancel { padding: 8px 20px; background: #fff; color: #555; border: 1px solid #d9d9d9; border-radius: 6px; text-decoration: none; font-size: 14px; }
</style>
