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

      <!-- Mount Settings -->
      <section v-if="activeSection === 'mounts'" class="config-section">
        <h3>📁 文件挂载点管理</h3>
        <div class="info-banner">每个挂载点将作为根目录下的一个虚拟目录显示。单挂载点时 / 直接显示文件内容。</div>
        <div class="mount-list" v-if="mounts.length">
          <div class="mount-header">
            <span class="mh-name">挂载名称</span>
            <span class="mh-path">文件系统路径</span>
            <span class="mh-actions">操作</span>
          </div>
          <div v-for="m in mounts" :key="m.name" class="mount-row" :class="{ editing: editingMount === m.name }">
            <span class="mh-name">{{ m.name }}</span>
            <span class="mh-path">{{ m.path }}</span>
            <span class="mh-actions">
              <button class="btn-edit-sm" @click="startEditMount(m)">编辑</button>
              <button class="btn-edit-sm btn-danger" @click="doDeleteMount(m.name)">删除</button>
            </span>
          </div>
        </div>
        <div v-else class="empty-logs">暂无挂载点</div>

        <!-- Add Mount Form -->
        <div class="mount-form" v-if="showMountForm">
          <h4>{{ editingMount ? '编辑挂载点' : '添加挂载点' }}</h4>
          <div class="form-grid">
            <div class="form-item">
              <label>挂载名称</label>
              <input v-model="mountForm.name" placeholder="例如: Documents" />
            </div>
            <div class="form-item full">
              <label>文件系统路径</label>
              <input v-model="mountForm.path" placeholder="例如: /home/user/Documents" />
            </div>
          </div>
          <div class="dialog-actions" style="margin-top:16px">
            <button class="btn-sm" @click="showMountForm = false; editingMount = null">取消</button>
            <button class="btn-sm btn-primary" @click="saveMount" :disabled="!mountForm.name || !mountForm.path">保存</button>
          </div>
        </div>
        <button class="btn-tool" @click="showAddMountForm" style="margin-top:12px">+ 添加挂载点</button>
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

      <!-- Auth Logs -->
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
                <td class="nowrap">{{ log.time.replace('T', ' ').split(' ')[1].split('.')[0] }}</td>
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

      <!-- System Logs -->
      <section v-if="activeSection === 'syslogs'" class="config-section">
        <div class="section-header">
          <h3>📋 系统运行日志</h3>
          <button class="btn-refresh" @click="loadSystemLogs">刷新</button>
        </div>
        <div class="syslogs-wrapper" ref="syslogContainer">
          <div v-for="(l, i) in systemLogs" :key="i" class="syslog-line" :class="'lv-' + l.level.toLowerCase()">
            <span class="sl-time">[{{ l.time.split('T')[1].split('.')[0] }}]</span>
            <span class="sl-lv">[{{ l.level }}]</span>
            <span class="sl-name">[{{ l.name }}]</span>
            <span class="sl-msg">{{ l.message }}</span>
          </div>
          <div v-if="!systemLogs.length" class="empty-logs">暂无系统日志</div>
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
      { id: 'mounts', label: '文件挂载', icon: '📁' },
      { id: 'mcp', label: 'AI 服务', icon: '🤖' },
      { id: 'logs', label: '安全审计', icon: '🛡️' },
      { id: 'syslogs', label: '系统日志', icon: '📋' },
    ],
    serverConfig: {},
    settings: {},
    authLogs: [],
    systemLogs: [],
    editingKey: null,
    editValue: '',
    editableDefs: SETTING_DEFS,
    _logTimer: null,
    mounts: [],
    showMountForm: false,
    editingMount: null,
    mountForm: { name: '', path: '' },
  }),
  computed: {
    mcpSafetyLabel() {
      const mode = this.serverConfig.mcp_safety_mode
      const map = { 'allow': '允许所有操作', 'confirm': '需要人工确认', 'safe': '完全禁止写操作' }
      return map[mode] || mode
    }
  },
  async mounted() { 
    await this.load()
    await this.loadMounts()
    this._logTimer = setInterval(() => {
      if (this.activeSection === 'syslogs') this.loadSystemLogs()
    }, 5000)
  },
  beforeUnmount() { clearInterval(this._logTimer) },
  watch: {
    activeSection(n) { if (n === 'mounts') this.loadMounts() },
  },
  methods: {
    async load() {
      try { this.serverConfig = await api.serverConfig() } catch(e) {}
      try { 
        const raw = await api.listSettings()
        const processed = { ...raw }
        this.editableDefs.forEach(d => {
          if (d.type === 'check') processed[d.key] = raw[d.key] === 'True'
        })
        this.settings = processed
      } catch(e) {}
      await this.loadLogs()
      await this.loadSystemLogs()
    },
    async loadLogs() {
      try { this.authLogs = await api.authLogs(30) } catch(e) {}
    },
    async loadSystemLogs() {
      try { 
        this.systemLogs = await api.systemLogs() 
        this.$nextTick(() => {
          const el = this.$refs.syslogContainer
          if (el) el.scrollTop = el.scrollHeight
        })
      } catch(e) {}
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

    // Mounts
    async loadMounts() {
      try { this.mounts = await api.listMounts() } catch(e) { this.mounts = [] }
    },
    showAddMountForm() {
      this.editingMount = null
      this.mountForm = { name: '', path: '' }
      this.showMountForm = true
    },
    startEditMount(m) {
      this.editingMount = m.name
      this.mountForm = { name: m.name, path: m.path }
      this.showMountForm = true
    },
    async saveMount() {
      const { name, path } = this.mountForm
      if (!name || !path) return
      try {
        if (this.editingMount) {
          await api.updateMount(this.editingMount, name, path)
        } else {
          await api.addMount(name, path)
        }
        this.showMountForm = false
        this.editingMount = null
        await this.loadMounts()
      } catch(e) { alert('保存失败：' + (e.message || e)) }
    },
    async doDeleteMount(name) {
      if (!confirm(`确认删除挂载点「${name}」？`)) return
      try {
        await api.deleteMount(name)
        await this.loadMounts()
      } catch(e) { alert('删除失败：' + (e.message || e)) }
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

.mount-list { border: 1px solid #f0f0f0; border-radius: 8px; overflow: hidden; }
.mount-header, .mount-row { display: flex; padding: 12px 16px; border-bottom: 1px solid #f0f0f0; align-items: center; }
.mount-header { background: #fafafa; font-weight: 600; color: #666; font-size: 13px; }
.mount-row:last-child { border-bottom: none; }
.mount-row.editing { background: #e6f4ff; }
.mh-name { width: 30%; }
.mh-path { flex: 1; color: #888; font-family: monospace; font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.mh-actions { width: 120px; text-align: right; display: flex; gap: 6px; justify-content: flex-end; }
.btn-danger { color: #ff4d4f; border-color: #ff4d4f; }
.mount-form { margin-top: 20px; padding: 20px; background: #fafafa; border-radius: 8px; border: 1px solid #e8e8e8; }
.mount-form h4 { margin: 0 0 16px; }

.syslogs-wrapper { margin-top: 16px; background: #1e1e1e; color: #d4d4d4; padding: 12px; border-radius: 8px; font-family: monospace; font-size: 12px; height: 400px; overflow-y: auto; line-height: 1.6; }
.syslog-line { margin-bottom: 2px; white-space: pre-wrap; word-break: break-all; }
.sl-time { color: #888; margin-right: 8px; }
.sl-lv { font-weight: bold; margin-right: 8px; }
.sl-name { color: #569cd6; margin-right: 8px; }
.lv-info .sl-lv { color: #52c41a; }
.lv-warning .sl-lv { color: #faad14; }
.lv-error .sl-lv { color: #f5222d; }
.lv-debug .sl-lv { color: #888; }
</style>
