<template>
  <div class="dashboard">
    <div class="stats-grid">
      <div class="stat-card glass no-transition">
        <div class="stat-icon-box bg-blue">
          <Users :size="24" />
        </div>
        <div class="stat-info">
          <div class="stat-num">{{ stats.contacts_count }}</div>
          <div class="stat-label">联系人</div>
        </div>
      </div>
      <div class="stat-card glass no-transition">
        <div class="stat-icon-box bg-green">
          <CalendarDays :size="24" />
        </div>
        <div class="stat-info">
          <div class="stat-num">{{ stats.events_count }}</div>
          <div class="stat-label">日程事件</div>
        </div>
      </div>
      <div class="stat-card glass no-transition">
        <div class="stat-icon-box bg-orange">
          <FileText :size="24" />
        </div>
        <div class="stat-info">
          <div class="stat-num">{{ stats.files_count }}</div>
          <div class="stat-label">存储文件</div>
        </div>
      </div>
      <div class="stat-card glass no-transition">
        <div class="stat-icon-box bg-purple">
          <HardDrive :size="24" />
        </div>
        <div class="stat-info">
          <div class="stat-num">{{ stats.disk_used_mb }} MB</div>
          <div class="stat-label">空间占用</div>
        </div>
      </div>
    </div>

    <div class="system-grid">
      <div class="info-section glass no-transition">
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
            <span class="info-val status-ok">
              <ShieldCheck :size="14" /> 正常运行
            </span>
          </div>
        </div>
      </div>

      <div class="info-section welcome-card no-transition">
        <div class="welcome-content">
          <h3>欢迎回来！</h3>
          <p>PersonalDAV 为您的数字生活保驾护航。您的数据已通过加密连接安全同步。</p>
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

export default {
  components: { 
    Users, CalendarDays, FileText, HardDrive, 
    Server, ChevronRight, ShieldCheck, Zap
  },
  data: () => ({ stats: {} }),
  async mounted() {
    try {
      this.stats = await api.stats()
    } catch (e) {}
  },
  computed: {
    uptime() {
      const s = Math.floor(this.stats.uptime || 0)
      const h = Math.floor(s / 3600)
      const m = Math.floor((s % 3600) / 60)
      return `${h} 小时 ${m} 分钟`
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

.stat-num { font-size: 32px; font-weight: 800; color: var(--text-primary); line-height: 1.1; letter-spacing: -1px; }
.stat-label { color: var(--text-secondary); font-size: 14px; margin-top: 4px; font-weight: 600; }

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

.welcome-card {
  background: linear-gradient(135deg, var(--brand) 0%, var(--brand-hover) 100%);
  color: white;
  border: none;
  display: flex;
  align-items: center;
  justify-content: space-between;
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
