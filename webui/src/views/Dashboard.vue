<template>
  <div class="dashboard">
    <div class="stats-grid">
      <div class="stat-card glass">
        <div class="stat-icon-box bg-blue">
          <Users :size="24" />
        </div>
        <div class="stat-info">
          <div class="stat-num">{{ stats.contacts_count }}</div>
          <div class="stat-label">联系人</div>
        </div>
      </div>
      <div class="stat-card glass">
        <div class="stat-icon-box bg-green">
          <CalendarDays :size="24" />
        </div>
        <div class="stat-info">
          <div class="stat-num">{{ stats.events_count }}</div>
          <div class="stat-label">日程事件</div>
        </div>
      </div>
      <div class="stat-card glass">
        <div class="stat-icon-box bg-orange">
          <FileText :size="24" />
        </div>
        <div class="stat-info">
          <div class="stat-num">{{ stats.files_count }}</div>
          <div class="stat-label">存储文件</div>
        </div>
      </div>
      <div class="stat-card glass">
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
      <div class="info-section glass">
        <h3><Server :size="18" /> 系统概览</h3>
        <div class="info-list">
          <div class="info-item">
            <span class="info-label">版本</span>
            <span class="info-val tag">{{ stats.version }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">运行时长</span>
            <span class="info-val">{{ uptime }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">健康状态</span>
            <span class="info-val text-success">正常运行</span>
          </div>
        </div>
      </div>

      <div class="info-section glass welcome-card">
        <h3>欢迎使用 PersonalDAV</h3>
        <p>您的全能 DAV 服务已就绪。您可以从侧边栏管理您的联系人、日历和文件。</p>
        <div class="welcome-actions">
          <router-link to="/files" class="btn-link">查看文件 <ChevronRight :size="14" /></router-link>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { 
  Users, CalendarDays, FileText, HardDrive, 
  Server, ChevronRight 
} from 'lucide-vue-next'
import api from '../api.js'

export default {
  components: { 
    Users, CalendarDays, FileText, HardDrive, 
    Server, ChevronRight 
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
.dashboard { display: flex; flex-direction: column; gap: 24px; }

.stats-grid { 
  display: grid; 
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); 
  gap: 20px; 
}

.stat-card { 
  background: var(--bg-card); 
  border-radius: var(--radius-lg); 
  padding: 24px; 
  display: flex;
  align-items: center;
  gap: 20px;
  box-shadow: var(--shadow-sm);
  transition: all .3s ease;
  border: 1px solid var(--border-base);
}
.stat-card:hover {
  transform: translateY(-4px);
  box-shadow: var(--shadow-md);
  border-color: var(--brand);
}

.stat-icon-box {
  width: 56px;
  height: 56px;
  border-radius: var(--radius-md);
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
}
.bg-blue { background: linear-gradient(135deg, #1677ff, #0050b3); }
.bg-green { background: linear-gradient(135deg, #52c41a, #237804); }
.bg-orange { background: linear-gradient(135deg, #faad14, #ad6800); }
.bg-purple { background: linear-gradient(135deg, #722ed1, #391085); }

.stat-info { display: flex; flex-direction: column; }
.stat-num { font-size: 28px; font-weight: 700; color: var(--text-primary); line-height: 1.2; }
.stat-label { color: var(--text-secondary); font-size: 14px; margin-top: 2px; }

.system-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 24px;
}

.info-section { 
  background: var(--bg-card); 
  border-radius: var(--radius-lg); 
  padding: 24px; 
  box-shadow: var(--shadow-sm); 
  border: 1px solid var(--border-base);
}
.info-section h3 { 
  margin: 0 0 20px; 
  font-size: 16px; 
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--text-primary);
}

.info-list { display: flex; flex-direction: column; gap: 16px; }
.info-item { display: flex; justify-content: space-between; align-items: center; }
.info-label { color: var(--text-secondary); font-size: 14px; }
.info-val { font-weight: 500; font-size: 14px; }
.tag { 
  background: var(--bg-info); 
  color: var(--brand); 
  padding: 2px 8px; 
  border-radius: 4px; 
  font-family: monospace; 
}

.welcome-card {
  background: linear-gradient(135deg, var(--brand) 0%, var(--brand-hover) 100%);
  color: white;
  border: none;
}
.welcome-card h3 { color: white; font-size: 20px; }
.welcome-card p { opacity: 0.9; line-height: 1.6; font-size: 14px; }
.welcome-actions { margin-top: 24px; }
.btn-link { 
  color: white; 
  text-decoration: none; 
  font-weight: 600; 
  display: inline-flex; 
  align-items: center; 
  gap: 4px;
  background: rgba(255,255,255,0.2);
  padding: 8px 16px;
  border-radius: var(--radius-sm);
  transition: .2s;
}
.btn-link:hover { background: rgba(255,255,255,0.3); }

.text-success { color: #52c41a; }

@media (max-width: 1024px) {
  .system-grid { grid-template-columns: 1fr; }
}
</style>
