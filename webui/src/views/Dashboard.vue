<template>
  <div class="dashboard">
    <div class="stats-grid">
      <div v-for="s in statDefs" :key="s.label" class="stat-card glass">
        <template v-if="loading">
          <div class="stat-icon-box" :class="s.bg" style="visibility:hidden;"><component :is="s.icon" :size="24" /></div>
          <div class="stat-info" style="flex:1;"><Skeleton width="60%" /><Skeleton width="40%" /></div>
        </template>
        <template v-else>
          <template v-if="s.key === 'disk_used_mb'">
            <div class="disk-ring-wrap">
              <svg class="disk-ring" viewBox="0 0 44 44">
                <circle cx="22" cy="22" r="18" fill="none" stroke="#eef1f5" stroke-width="4" />
                <circle cx="22" cy="22" r="18" fill="none" stroke="#b9c0ca" stroke-width="4"
                  :stroke-dasharray="`${113.1 * diskOtherRatio} 113.1`"
                  :stroke-dashoffset="-113.1 * diskUsedRatio"
                  transform="rotate(-90 22 22)" class="ring-fill" />
                <circle cx="22" cy="22" r="18" fill="none" stroke="var(--brand)" stroke-width="4"
                  :stroke-dasharray="`${113.1 * diskUsedRatio} 113.1`"
                  stroke-dashoffset="0" transform="rotate(-90 22 22)"
                  class="ring-fill" />
              </svg>
              <span class="disk-ring-text">{{ diskPercentLabel }}</span>
            </div>
            <div class="stat-info">
              <div class="stat-num">{{ stats[s.key] }}{{ s.unit }}</div>
              <div class="stat-label">{{ s.label }}</div>
              <div class="stat-detail">{{ diskDetail }}</div>
              <div class="disk-legend">
                <span><i class="disk-dot dot-used"></i>数据</span>
                <span><i class="disk-dot dot-other"></i>其他</span>
                <span><i class="disk-dot dot-free"></i>剩余</span>
              </div>
              <div v-if="stats.disk_over_quota" class="stat-trend trend-down">已超过分配空间</div>
              <div v-if="s.trend" class="stat-trend" :class="s.trend[0] === '+' ? 'trend-up' : 'trend-down'">{{ s.trend }}</div>
            </div>
          </template>
          <template v-else>
            <div class="stat-icon-box" :class="s.bg"><component :is="s.icon" :size="24" /></div>
            <div class="stat-info">
              <div class="stat-num">{{ stats[s.key] }}{{ s.unit }}</div>
              <div class="stat-label">{{ s.label }}</div>
              <div v-if="s.trend" class="stat-trend" :class="s.trend[0] === '+' ? 'trend-up' : 'trend-down'">{{ s.trend }}</div>
            </div>
          </template>
        </template>
      </div>
    </div>

    <div class="system-grid">
      <div class="info-section glass">
        <h3><Server :size="18" /> 系统概览</h3>
        <div class="info-list">
          <div class="info-item">
            <span class="info-label">当前版本</span>
            <span class="info-val tag">{{ stats.version }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">运行时长</span>
            <span class="info-val">{{ uptime }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">健康状态</span>
            <span class="info-val" :class="healthStatus.class">
              <ShieldCheck :size="14" /> {{ healthStatus.text }}
            </span>
          </div>
        </div>
      </div>

      <div class="info-section welcome-card">
        <div class="welcome-content">
          <h3>欢迎回来！</h3>
          <p>{{ welcomeMessage }}</p>
          <div class="welcome-actions">
            <router-link to="/files" class="btn-welcome">
              立即开始管理 <ChevronRight :size="16" />
            </router-link>
          </div>
        </div>
        <div class="welcome-bg-icon">
          <Zap :size="120" />
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { 
  Users, CalendarDays, FileText, HardDrive, 
  Server, ChevronRight, ShieldCheck, Zap
} from 'lucide-vue-next'
import api from '../api.js'
import Skeleton from '../components/Skeleton.vue'

export default {
  components: { 
    Users, CalendarDays, FileText, HardDrive, 
    Server, ChevronRight, ShieldCheck, Zap, Skeleton
  },
  data: () => ({ stats: { disk_total_mb: 0 }, health: { status: 'unknown' }, serverConfig: null, loading: true, _refreshTimer: null, _failCount: 0 }),
  async mounted() {
    this.loadData()
    this._refreshTimer = setInterval(() => this.loadData(), 15000)
  },
  beforeUnmount() {
    if (this._refreshTimer) { clearInterval(this._refreshTimer); this._refreshTimer = null }
  },
  methods: {
    async loadData() {
      try {
        [this.stats, this.health, this.serverConfig] = await Promise.all([api.stats(), api.health(), api.serverConfig()])
        this._failCount = 0
      } catch (e) {
        this._failCount++
        console.error('Failed to load dashboard data:', e)
      }
      this.loading = false
    },
  },
  computed: {
    healthStatus() {
      if (this._failCount >= 2) return { text: '服务器掉线', class: 'status-fail' }
      if (this.health.status === 'ok') return { text: '正常运行', class: 'status-ok' }
      return { text: '服务器异常', class: 'status-fail' }
    },
    diskUsedRatio() {
      const total = Number(this.stats.disk_total_mb) || 0
      if (total <= 0) return 0
      return Math.min(1, (Number(this.stats.disk_used_mb) || 0) / total)
    },
    diskOtherRatio() {
      const total = Number(this.stats.disk_total_mb) || 0
      if (total <= 0) return 0
      const other = Number(this.stats.disk_other_mb) || 0
      return Math.min(1 - this.diskUsedRatio, other / total)
    },
    diskPercent() {
      return this.diskUsedRatio + this.diskOtherRatio
    },
    diskPercentLabel() {
      const total = Number(this.stats.disk_total_mb) || 0
      if (total <= 0) return '—'
      if (this.stats.disk_over_quota) return '>100%'
      return `${Math.round(this.diskPercent * 100)}%`
    },
    diskDetail() {
      const used = Number(this.stats.disk_used_mb) || 0
      const total = Number(this.stats.disk_total_mb) || 0
      if (!total) return used.toFixed(1) + ' MB'
      return used.toFixed(1) + ' / ' + total.toFixed(1) + ' MB'
    },
    welcomeMessage() {
      const proto = this.serverConfig?.server_protocol || 'http_https'
      const ssl = this.serverConfig?.ssl_enabled || false
      if (proto === 'https_only') return 'PersonalDAV 为您的数字生活保驾护航。您的数据已通过 HTTPS 加密连接安全同步。'
      if (proto === 'http_https' && ssl) return 'PersonalDAV 为您的数字生活保驾护航。您的数据已通过加密连接安全同步。'
      return 'PersonalDAV 为您的数字生活保驾护航。您的数据通过 HTTP 连接同步。'
    },
    uptime() {
      const s = Math.floor(this.stats.uptime || 0)
      const h = Math.floor(s / 3600)
      const m = Math.floor((s % 3600) / 60)
      return `${h} 小时 ${m} 分钟`
    },
    statDefs() {
      return [
        { key: 'contacts_count', label: '联系人', icon: 'Users', bg: 'bg-blue', unit: '', trend: this.stats.trends?.contacts_count || '' },
        { key: 'events_count', label: '日程事件', icon: 'CalendarDays', bg: 'bg-green', unit: '', trend: this.stats.trends?.events_count || '' },
        { key: 'files_count', label: '存储文件', icon: 'FileText', bg: 'bg-orange', unit: '', trend: this.stats.trends?.files_count || '' },
        { key: 'disk_used_mb', label: '空间占用', icon: 'HardDrive', bg: 'bg-purple', unit: ' MB', trend: this.stats.trends?.disk_used_mb || '' },
      ]
    },
  },
}
</script>

<style scoped>
.dashboard { display: flex; flex-direction: column; gap: 24px; padding: 4px; }

.stats-grid { 
  display: grid; 
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); 
  gap: 20px; 
}

.stat-card { 
  background: var(--bg-card); 
  border-radius: var(--radius-lg); 
  padding: 28px; 
  display: flex;
  align-items: center;
  gap: 24px;
  box-shadow: var(--shadow-sm);
  transition: all .3s cubic-bezier(0.4, 0, 0.2, 1);
  border: 1px solid var(--border-base);
}
.stat-card:hover {
  transform: translateY(-5px);
  box-shadow: var(--shadow-lg);
  border-color: var(--brand);
}

.stat-icon-box {
  width: 60px;
  height: 60px;
  border-radius: var(--radius-md);
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  box-shadow: 0 8px 16px rgba(0,0,0,0.1);
}
.bg-blue { background: linear-gradient(135deg, #1677ff, #0050b3); }
.bg-green { background: linear-gradient(135deg, #52c41a, #237804); }
.bg-orange { background: linear-gradient(135deg, #faad14, #ad6800); }
.bg-purple { background: linear-gradient(135deg, #722ed1, #391085); }

.disk-ring-wrap { position: relative; width: 72px; height: 72px; flex-shrink: 0; display: flex; align-items: center; justify-content: center; }
.disk-ring { width: 72px; height: 72px; }
.ring-fill { transition: stroke-dashoffset 0.8s cubic-bezier(0.34, 1.56, 0.64, 1); }
.disk-ring-text { position: absolute; font-size: 12px; font-weight: 800; color: var(--text-primary); }
.stat-detail { font-size: 11px; color: var(--text-quaternary); margin-top: 2px; }
.disk-legend { display: flex; gap: 10px; margin-top: 5px; font-size: 10px; color: var(--text-tertiary); flex-wrap: wrap; }
.disk-legend span { display: inline-flex; align-items: center; gap: 4px; }
.disk-dot { width: 7px; height: 7px; border-radius: 50%; display: inline-block; }
.dot-used { background: var(--brand); }
.dot-other { background: #b9c0ca; }
.dot-free { background: #eef1f5; border: 1px solid #d5dae2; }

.stat-num { font-size: 32px; font-weight: 800; color: var(--text-primary); line-height: 1.1; letter-spacing: -1px; }
.stat-label { color: var(--text-secondary); font-size: 14px; margin-top: 4px; font-weight: 600; }
.stat-trend { font-size: 12px; font-weight: 600; margin-top: 6px; }
.trend-up { color: #52c41a; }
.trend-down { color: var(--danger); }

.system-grid {
  display: grid;
  grid-template-columns: 1fr 1.5fr;
  gap: 24px;
}

.info-section { 
  background: var(--bg-card); 
  border-radius: var(--radius-lg); 
  padding: 32px; 
  box-shadow: var(--shadow-sm); 
  border: 1px solid var(--border-base);
  position: relative;
  overflow: hidden;
  transition: all .3s cubic-bezier(0.4, 0, 0.2, 1);
}
.info-section:hover {
  transform: translateY(-3px);
  box-shadow: var(--shadow-lg);
  border-color: var(--brand);
}
.info-section h3 { 
  margin: 0 0 24px; 
  font-size: 18px; 
  display: flex;
  align-items: center;
  gap: 10px;
  color: var(--text-primary);
  font-weight: 700;
}

.info-list { display: flex; flex-direction: column; gap: 20px; }
.info-item { display: flex; justify-content: space-between; align-items: center; }
.info-label { color: var(--text-secondary); font-size: 14px; font-weight: 500; }
.info-val { font-weight: 700; font-size: 15px; color: var(--text-primary); }
.tag { 
  background: var(--bg-info); 
  color: var(--brand); 
  padding: 4px 12px; 
  border-radius: 20px; 
  font-family: 'Fira Code', monospace;
  font-size: 13px;
}

.status-ok { color: #52c41a; display: flex; align-items: center; gap: 6px; font-weight: 700; }
.status-fail { color: var(--danger); display: flex; align-items: center; gap: 6px; font-weight: 700; }

.welcome-card {
  background: linear-gradient(135deg, var(--brand) 0%, var(--brand-hover) 100%);
  color: white;
  border: none;
  display: flex;
  align-items: center;
  justify-content: space-between;
  transition: all .3s cubic-bezier(0.4, 0, 0.2, 1);
}
.welcome-card:hover {
  transform: translateY(-3px);
  box-shadow: var(--shadow-xl);
}
.welcome-content { position: relative; z-index: 2; }
.welcome-card h3 { color: white; font-size: 24px; margin-bottom: 12px; font-weight: 800; }
.welcome-card p { opacity: 0.9; line-height: 1.6; font-size: 15px; max-width: 400px; }
.welcome-actions { margin-top: 32px; }
.btn-welcome { 
  color: var(--brand); 
  text-decoration: none; 
  font-weight: 700; 
  display: inline-flex; 
  align-items: center; 
  gap: 8px;
  background: white;
  padding: 12px 24px;
  border-radius: var(--radius-md);
  transition: all .2s;
  font-size: 15px;
}
.btn-welcome:hover { transform: scale(1.05); box-shadow: 0 8px 20px rgba(0,0,0,0.15); }

.welcome-bg-icon { position: absolute; right: -20px; bottom: -20px; opacity: 0.1; transform: rotate(-15deg); z-index: 1; }

@media (max-width: 1024px) {
  .system-grid { grid-template-columns: 1fr; }
}

@media (max-width: 600px) {
  .stat-card { padding: 20px; gap: 16px; }
  .stat-num { font-size: 24px; }
  .welcome-card { padding: 24px; }
  .welcome-bg-icon { display: none; }
}
</style>
