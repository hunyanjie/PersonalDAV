<template>
  <div class="login-page">
    <div class="login-bg-pattern" :style="{ '--brand-color': currentBrandColor }"></div>
    <div class="login-card glass">
      <div class="login-header">
        <div class="login-logo">P</div>
        <h1>PersonalDAV</h1>
        <p class="subtitle">全能 DAV 服务管理界面</p>
      </div>
      
      <div v-if="error" class="error-box">
        <AlertCircle :size="16" />
        <span>{{ error }}</span>
      </div>

      <form @submit.prevent="doLogin" class="login-form">
        <div class="input-group">
          <label>管理员密码</label>
          <div class="input-wrapper">
            <Lock :size="18" class="input-icon" />
            <input v-model="password" type="password" placeholder="请输入密码..." autofocus />
          </div>
        </div>
        <button type="submit" class="login-btn" :disabled="loading">
          <span v-if="!loading">进入控制台</span>
          <span v-else class="loading-spinner"></span>
        </button>
      </form>

      <div class="login-footer">
        <p>安全连接已建立</p>
      </div>
    </div>
  </div>
</template>

<script>
import { Lock, AlertCircle } from 'lucide-vue-next'
import api from '../api.js'

export default {
  components: { Lock, AlertCircle },
  data: () => ({ password: '', loading: false, error: '' }),
  computed: {
    currentBrandColor() {
      // Access CSS variables or fallback
      return 'var(--brand)'
    }
  },
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
        this.error = e.message || '登录失败，请检查密码'
      } finally { this.loading = false }
    },
  },
}
</script>

<style scoped>
.login-page { 
  display: flex; 
  align-items: center; 
  justify-content: center; 
  min-height: 100vh; 
  background: #f0f2f5; 
  position: relative;
  overflow: hidden;
}

.login-bg-pattern {
  position: absolute;
  top: -50%;
  left: -50%;
  width: 200%;
  height: 200%;
  background: radial-gradient(circle at center, var(--brand-color) 0%, transparent 70%);
  opacity: 0.08;
  animation: rotate 60s linear infinite;
  z-index: 0;
}

@keyframes rotate {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.login-card { 
  background: rgba(255, 255, 255, 0.8); 
  padding: 48px; 
  border-radius: var(--radius-xl); 
  box-shadow: var(--shadow-xl); 
  width: 400px; 
  text-align: center; 
  z-index: 10;
  border: 1px solid var(--glass-border);
}

.login-header { margin-bottom: 32px; }
.login-logo {
  width: 64px;
  height: 64px;
  background: var(--brand);
  color: white;
  border-radius: var(--radius-lg);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 32px;
  font-weight: bold;
  margin: 0 auto 20px;
  box-shadow: 0 8px 16px hsla(var(--brand-hue) var(--brand-sat) var(--brand-lit) / 0.2);
}
.login-card h1 { margin: 0 0 8px; font-size: 28px; color: var(--text-primary); letter-spacing: -0.5px; }
.subtitle { color: var(--text-secondary); margin: 0; font-size: 15px; }

.error-box { 
  background: var(--bg-danger); 
  border: 1px solid var(--danger-border); 
  color: var(--danger-text); 
  padding: 12px 16px; 
  border-radius: var(--radius-md); 
  margin-bottom: 24px; 
  font-size: 14px; 
  display: flex;
  align-items: center;
  gap: 8px;
  justify-content: center;
}

.login-form { text-align: left; }
.input-group { margin-bottom: 24px; }
.input-group label { display: block; margin-bottom: 8px; font-size: 13px; font-weight: 600; color: var(--text-secondary); }

.input-wrapper { position: relative; }
.input-icon { position: absolute; left: 12px; top: 50%; transform: translateY(-50%); color: var(--text-tertiary); }
.input-wrapper input { 
  width: 100%; 
  padding: 12px 12px 12px 40px; 
  border: 1px solid var(--border-input); 
  border-radius: var(--radius-md); 
  font-size: 16px; 
  box-sizing: border-box; 
  background: white;
  transition: all .2s;
}
.input-wrapper input:focus {
  border-color: var(--brand);
  outline: none;
  box-shadow: 0 0 0 4px var(--brand-ring);
}

.login-btn { 
  width: 100%; 
  padding: 14px; 
  background: var(--brand); 
  color: var(--text-inverse); 
  border: none; 
  border-radius: var(--radius-md); 
  font-size: 16px; 
  font-weight: 600;
  cursor: pointer; 
  transition: all .2s;
  box-shadow: 0 4px 12px hsla(var(--brand-hue) var(--brand-sat) var(--brand-lit) / 0.2);
}
.login-btn:hover { background: var(--brand-hover); transform: translateY(-1px); box-shadow: 0 6px 16px hsla(var(--brand-hue) var(--brand-sat) var(--brand-lit) / 0.3); }
.login-btn:active { transform: translateY(0); }
.login-btn:disabled { opacity: .6; cursor: not-allowed; }

.login-footer { margin-top: 32px; color: var(--text-quaternary); font-size: 12px; }

.loading-spinner {
  display: inline-block;
  width: 20px;
  height: 20px;
  border: 2px solid rgba(255,255,255,.3);
  border-radius: 50%;
  border-top-color: white;
  animation: spin 1s ease-in-out infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
</style>
