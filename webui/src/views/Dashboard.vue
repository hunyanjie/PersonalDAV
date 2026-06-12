<template>
  <div class="dashboard">
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-num">{{ stats.contacts_count }}</div>
        <div class="stat-label">联系人</div>
      </div>
      <div class="stat-card">
        <div class="stat-num">{{ stats.events_count }}</div>
        <div class="stat-label">事件</div>
      </div>
      <div class="stat-card">
        <div class="stat-num">{{ stats.files_count }}</div>
        <div class="stat-label">文件</div>
      </div>
      <div class="stat-card">
        <div class="stat-num">{{ stats.disk_used_mb }} MB</div>
        <div class="stat-label">磁盘占用</div>
      </div>
    </div>
    <div class="info-section">
      <p><strong>版本：</strong> {{ stats.version }}</p>
      <p><strong>运行时间：</strong> {{ uptime }}</p>
    </div>
  </div>
</template>

<script>
import api from '../api.js'
export default {
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
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
.stat-card { background: var(--bg-card); border-radius: 8px; padding: 24px; text-align: center; box-shadow: var(--shadow-sm); }
.stat-num { font-size: 32px; font-weight: bold; color: var(--brand); }
.stat-label { color: var(--text-secondary); margin-top: 4px; font-size: 14px; }
.info-section { background: var(--bg-card); border-radius: 8px; padding: 20px; box-shadow: var(--shadow-sm); }
.info-section p { margin: 4px 0; font-size: 14px; }
</style>
