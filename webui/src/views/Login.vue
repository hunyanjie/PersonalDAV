<template>
  <div class="login-page">
    <div class="login-card">
      <h1>PersonalDAV</h1>
      <p class="subtitle">Web 管理界面</p>
      <div v-if="error" class="error">{{ error }}</div>
      <form @submit.prevent="doLogin">
        <input v-model="password" type="password" placeholder="管理员密码" autofocus />
        <button type="submit" :disabled="loading">{{ loading ? '登录中...' : '登录' }}</button>
      </form>
    </div>
  </div>
</template>

<script>
import api from '../api.js'
export default {
  data: () => ({ password: '', loading: false, error: '' }),
  methods: {
    browserFingerprint() {
      const parts = [
        navigator.userAgent || '',
        navigator.language || '',
        screen.width + 'x' + screen.height,
        screen.colorDepth || '',
        navigator.platform || '',
        new Date().getTimezoneOffset(),
      ]
      let s = parts.join('||')
      let h = 0
      for (let i = 0; i < s.length; i++) {
        h = ((h << 5) - h) + s.charCodeAt(i); h |= 0
      }
      return h.toString(16)
    },
    async doLogin() {
      this.loading = true; this.error = ''
      try {
        const res = await api.login(this.password, this.browserFingerprint())
        localStorage.setItem('token', res.token)
        this.$router.push('/')
      } catch (e) {
        this.error = e.message || '登录失败'
      } finally { this.loading = false }
    },
  },
}
</script>

<style scoped>
.login-page { display: flex; align-items: center; justify-content: center; min-height: 100vh; background: var(--bg-page); }
.login-card { background: var(--bg-card); padding: 40px; border-radius: 12px; box-shadow: var(--shadow-md); width: 360px; text-align: center; }
.login-card h1 { margin: 0 0 4px; font-size: 24px; }
.subtitle { color: var(--text-secondary); margin: 0 0 24px; font-size: 14px; }
.error { background: var(--bg-danger); border: 1px solid var(--danger-border); color: var(--danger-text); padding: 8px 12px; border-radius: 6px; margin-bottom: 16px; font-size: 14px; }
input { width: 100%; padding: 10px 12px; border: 1px solid var(--border-input); border-radius: 6px; font-size: 16px; box-sizing: border-box; margin-bottom: 16px; }
button { width: 100%; padding: 10px; background: var(--brand); color: var(--text-inverse); border: none; border-radius: 6px; font-size: 16px; cursor: pointer; }
button:disabled { opacity: .6; }
</style>
