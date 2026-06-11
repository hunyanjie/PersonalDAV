<template>
  <div class="settings-container">
    <div class="settings-nav">
      <button v-for="s in sections" :key="s.id" 
        class="nav-btn" :class="{ active: activeSection === s.id }"
        @click="activeSection = s.id">
        {{ s.icon }} {{ s.label }}
      </button>
    </div>

    <div class="settings-content">
      <!-- Server Settings -->
      <section v-if="activeSection === 'server'" class="config-section">
        <h3>🚀 服务器核心配置</h3>
        <div class="info-banner">只读信息，如需修改请编辑配置文件或在 GUI 中调整。</div>
        <div class="form-grid">
          <div class="form-item">
            <label>运行主机</label>
            <input :value="serverConfig.host" disabled />
          </div>
          <div class="form-item">
            <label>监听端口</label>
            <input :value="serverConfig.port" disabled />
          </div>
          <div class="form-item">
            <label>数据库路径</label>
            <input :value="serverConfig.db_path" disabled />
          </div>
          <div class="form-item">
            <label>文件根目录</label>
            <input :value="serverConfig.dav_root" disabled />
          </div>
          <div class="form-item">
            <label>日志级别</label>
            <select :value="serverConfig.log_level" disabled>
              <option>DEBUG</option><option>INFO</option><option>WARNING</option><option>ERROR</option>
            </select>
          </div>
        </div>
      </section>

      <!-- MCP Settings -->
      <section v-if="activeSection === 'mcp'" class="config-section">
        <h3>🤖 MCP (Model Context Protocol)</h3>
        <div class="form-grid">
          <div class="form-item full">
            <label class="checkbox-label">
              <input type="checkbox" :checked="serverConfig.mcp_enabled" disabled />
              启用 MCP 服务 (允许 AI 访问您的数据)
            </label>
          </div>
          <div class="form-item">
            <label>MCP 端口</label>
            <input :value="serverConfig.mcp_port" disabled />
          </div>
          <div class="form-item">
            <label>安全模式</label>
            <input :value="mcpSafetyLabel" disabled />
          </div>
          <div class="form-item full">
            <label class="checkbox-label">
              <input type="checkbox" :checked="serverConfig.mcp_readonly" disabled />
              只读模式 (禁止 AI 修改数据)
            </label>
          </div>
        </div>
      </section>

      <!-- App Settings -->
      <section v-if="activeSection === 'app'" class="config-section">
        <h3>⚙️ 可配置选项</h3>
        <div class="settings-list">
          <div v-for="def in editableDefs" :key="def.key" class="setting-row">
            <div class="setting-info">
              <div class="setting-label">{{ def.label }}</div>
              <div class="setting-key">{{ def.key }}</div>
            </div>
            <div class="setting-control">
              <template v-if="def.type === 'check'">
                <input type="checkbox" v-model="settings[def.key]" @change="doUpdate(def.key, settings[def.key])" />
              </template>
              <template v-else-if="def.type === 'combo'">
                <select v-model="settings[def.key]" @change="doUpdate(def.key, settings[def.key])">
                  <option v-for="opt in def.options" :key="opt.val" :value="opt.val">{{ opt.text }}</option>
                </select>
              </template>
              <template v-else>
                <div class="input-group">
                  <input v-if="editingKey === def.key" v-model="editValue" :type="def.inputType || 'text'" class="edit-input" />
                  <span v-else class="val-text">{{ settings[def.key] }}</span>
                  <button v-if="editingKey === def.key" class="btn-save-sm" @click="confirmUpdate(def)">保存</button>
                  <button v-if="editingKey === def.key" class="btn-cancel-sm" @click="editingKey = null">取消</button>
                  <button v-else class="btn-edit-sm" @click="startEdit(def.key, settings[def.key])">修改</button>
                </div>
              </template>
            </div>
          </div>
        </div>
      </section>

      <!-- Logs -->
      <section v-if="activeSection === 'logs'" class="config-section">
        <div class="section-header">
          <h3>🛡️ 鉴权审计日志</h3>
          <button class="btn-refresh" @click="loadLogs">刷新</button>
        </div>
        <div class="logs-wrapper">
          <table v-if="authLogs.length" class="logs-table">
            <thead><tr><th>时间</th><th>协议</th><th>详情</th><th>结果</th></tr></thead>
            <tbody>
              <tr v-for="log in authLogs" :key="log.id" :class="{ 'log-fail': !log.success }">
                <td class="nowrap">{{ log.time.split(' ')[1] }}</td>
                <td><span class="proto-tag">{{ log.method }}</span></td>
                <td :title="log.user_agent">{{ log.detail }}</td>
                <td>
                  <span class="status-dot" :class="log.success ? 'ok' : 'fail'"></span>
                  {{ log.success ? '通过' : '拒绝' }}
                </td>
              </tr>
            </tbody>
          </table>
          <div v-else class="empty-logs">暂无最近鉴权记录</div>
        </div>
      </section>
    </div>
  </div>
</template>

<script>
import api from '../api.js'

const SETTING_DEFS = [
  { key: 'auto_start_server', label: '启动时自动运行服务器', type: 'check' },
  { key: 'auto_check_update', label: '自动检查更新', type: 'check' },
  { key: 'default_status', label: '默认事件状态', type: 'combo', options: [
    { text: '已确认', val: 'CONFIRMED' }, { text: '暂定', val: 'TENTATIVE' }, { text: '已取消', val: 'CANCELLED' }
  ]},
  { key: 'default_priority', label: '默认优先级 (0-9)', type: 'text', inputType: 'number', min: 0, max: 9 },
  { key: 'sync_interval', label: '同步间隔 (分钟)', type: 'text', inputType: 'number', min: 5 },
  { key: 'ftp_encoding', label: 'FTP 文件编码', type: 'combo', options: [
    { text: 'UTF-8', val: 'utf-8' }, { text: 'GBK (中文)', val: 'gbk' }, { text: 'Big5', val: 'big5' }
  ]},
]

export default {
  data: () => ({
    activeSection: 'server',
    sections: [
      { id: 'server', label: '核心配置', icon: '🚀' },
      { id: 'app', label: '通用选项', icon: '⚙️' },
      { id: 'mcp', label: 'AI 服务', icon: '🤖' },
      { id: 'logs', label: '安全审计', icon: '🛡️' },
    ],
    serverConfig: {},
    settings: {},
    authLogs: [],
    editingKey: null,
    editValue: '',
    editableDefs: SETTING_DEFS,
  }),
  computed: {
    mcpSafetyLabel() {
      const mode = this.serverConfig.mcp_safety_mode
      const map = { 'allow': '允许所有操作', 'confirm': '需要人工确认', 'safe': '完全禁止写操作' }
      return map[mode] || mode
    }
  },
  async mounted() { await this.load() },
  methods: {
    async load() {
      try { this.serverConfig = await api.serverConfig() } catch(e) {}
      try { 
        const raw = await api.listSettings()
        // Type conversion for checkboxes
        const processed = { ...raw }
        this.editableDefs.forEach(d => {
          if (d.type === 'check') processed[d.key] = raw[d.key] === 'True'
        })
        this.settings = processed
      } catch(e) {}
      await this.loadLogs()
    },
    async loadLogs() {
      try { this.authLogs = await api.authLogs(30) } catch(e) {}
    },
    startEdit(key, value) {
      this.editingKey = key; this.editValue = value
    },
    async confirmUpdate(def) {
      let val = this.editValue
      if (def.inputType === 'number') {
        const n = parseInt(val)
        if (isNaN(n)) return alert('请输入数字')
        if (def.min !== undefined && n < def.min) return alert(`最小值: ${def.min}`)
        if (def.max !== undefined && n > def.max) return alert(`最大值: ${def.max}`)
        val = String(n)
      }
      await this.doUpdate(def.key, val)
      this.editingKey = null
    },
    async doUpdate(key, value) {
      try {
        const dbVal = typeof value === 'boolean' ? (value ? 'True' : 'False') : String(value)
        await api.updateSetting(key, dbVal)
        this.settings[key] = value
      } catch(e) { alert('保存失败') }
    },
  },
}
</script>

<style scoped>
.settings-container { display: flex; height: 100%; gap: 24px; }

.settings-nav { width: 180px; display: flex; flex-direction: column; gap: 8px; flex-shrink: 0; }
.nav-btn { display: flex; align-items: center; gap: 10px; padding: 12px 16px; border: none; background: transparent; border-radius: 8px; cursor: pointer; text-align: left; font-size: 14px; color: #666; transition: .2s; }
.nav-btn:hover { background: #eee; }
.nav-btn.active { background: #1677ff; color: #fff; font-weight: 500; }

.settings-content { flex: 1; background: #fff; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.04); padding: 24px; overflow-y: auto; }

.config-section h3 { margin: 0 0 20px; font-size: 18px; color: #1a1a1a; }
.info-banner { background: #f0f7ff; border: 1px solid #bae7ff; color: #0050b3; padding: 10px 16px; border-radius: 6px; font-size: 13px; margin-bottom: 24px; }

.form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
.form-item { display: flex; flex-direction: column; gap: 8px; }
.form-item.full { grid-column: span 2; }
.form-item label { font-size: 13px; color: #888; }
.form-item input, .form-item select { padding: 10px 12px; border: 1px solid #d9d9d9; border-radius: 6px; background: #fafafa; font-size: 14px; }
.form-item input:disabled { color: #555; }

.checkbox-label { display: flex; align-items: center; gap: 10px; color: #333 !important; cursor: pointer; }
.checkbox-label input { width: 18px; height: 18px; }

.settings-list { display: flex; flex-direction: column; }
.setting-row { display: flex; align-items: center; justify-content: space-between; padding: 16px 0; border-bottom: 1px solid #f0f0f0; }
.setting-info { flex: 1; }
.setting-label { font-size: 15px; font-weight: 500; color: #333; }
.setting-key { font-size: 12px; color: #999; font-family: monospace; margin-top: 2px; }

.setting-control select { padding: 6px 12px; border-radius: 4px; border: 1px solid #d9d9d9; }
.input-group { display: flex; align-items: center; gap: 8px; }
.val-text { color: #1677ff; font-weight: 500; }
.edit-input { width: 120px; padding: 6px 10px; border: 1px solid #1677ff; border-radius: 4px; }

.btn-edit-sm, .btn-save-sm, .btn-cancel-sm { padding: 4px 10px; border-radius: 4px; font-size: 12px; cursor: pointer; border: 1px solid #d9d9d9; background: #fff; }
.btn-save-sm { background: #1677ff; color: #fff; border-color: #1677ff; }
.btn-edit-sm:hover { border-color: #1677ff; color: #1677ff; }

.section-header { display: flex; justify-content: space-between; align-items: baseline; }
.btn-refresh { border: none; background: transparent; color: #1677ff; cursor: pointer; font-size: 13px; }

.logs-wrapper { margin-top: 10px; }
.logs-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.logs-table th { text-align: left; padding: 12px; border-bottom: 2px solid #f0f0f0; color: #888; font-weight: 500; }
.logs-table td { padding: 12px; border-bottom: 1px solid #f5f5f5; color: #555; }
.log-fail { background: #fff1f0; }
.nowrap { white-space: nowrap; }
.proto-tag { background: #f0f2f5; padding: 2px 6px; border-radius: 4px; font-size: 11px; }
.status-dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; margin-right: 4px; }
.status-dot.ok { background: #52c41a; }
.status-dot.fail { background: #ff4d4f; }
.empty-logs { text-align: center; padding: 40px; color: #ccc; }
</style>
