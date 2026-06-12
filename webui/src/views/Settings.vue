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

      <!-- Theme -->
      <section v-if="activeSection === 'theme'" class="config-section">
        <h3>🎨 主题自定义</h3>
        <div class="info-banner">选择预设主题或自定义 HSL 调色板。修改后即时生效，自动保存至浏览器本地。</div>

        <div class="theme-presets">
          <div class="preset-label">预设色板</div>
          <div class="preset-grid">
            <button v-for="p in presets" :key="p.name"
              class="preset-btn"
              :class="{ active: isPresetActive(p) }"
              :style="{ background: `hsl(${p.h}deg ${p.s}% ${p.l}%)` }"
              @click="applyPreset(p)"
              :title="p.name" />
          </div>
        </div>

        <div class="theme-custom">
          <h4>自定义调色</h4>
          <div class="hsl-row">
            <label>色相 <span class="hsl-val">{{ themeH }}°</span></label>
            <div class="slider-track hue-track" :style="{ background: hueTrackBg }">
              <input type="range" min="0" max="360" v-model.number="themeH" class="hsl-range" @input="applyCustom" />
            </div>
          </div>
          <div class="hsl-row">
            <label>饱和度 <span class="hsl-val">{{ themeS }}%</span></label>
            <div class="slider-track" :style="{ background: `linear-gradient(to right, hsl(${themeH}deg 0% ${themeL}%), hsl(${themeH}deg 100% ${themeL}%))` }">
              <input type="range" min="0" max="100" v-model.number="themeS" class="hsl-range" @input="applyCustom" />
            </div>
          </div>
          <div class="hsl-row">
            <label>明度 <span class="hsl-val">{{ themeL }}%</span></label>
            <div class="slider-track" :style="{ background: `linear-gradient(to right, hsl(${themeH}deg ${themeS}% 0%), hsl(${themeH}deg ${themeS}% 100%))` }">
              <input type="range" min="0" max="100" v-model.number="themeL" class="hsl-range" @input="applyCustom" />
            </div>
          </div>

          <div class="theme-preview">
            <div class="preview-label">当前品牌色</div>
            <div class="preview-block">
              <div class="preview-swatch" :style="{ background: currentBrandColor }"></div>
              <div class="preview-samples">
                <div class="sample" :style="{ background: currentBrandColor }"></div>
                <div class="sample sample-hover" :style="{ background: `hsl(${themeH}deg ${themeS}% ${Math.max(themeL-8,0)}%)` }"></div>
                <div class="sample sample-soft" :style="{ background: `hsl(${themeH}deg ${Math.max(themeS-34,0)}% ${Math.min(themeL+43,100)}%)` }"></div>
              </div>
            </div>
            <div class="preview-code">hsl({{ themeH }}deg {{ themeS }}% {{ themeL }}%)</div>
          </div>

          <button class="btn-sm" @click="resetTheme" style="margin-top:12px">恢复默认蓝色</button>
        </div>
      </section>
    </div>
  </div>
</template>

<script>
import api from '../api.js'

const PRESETS = [
  { name: '经典蓝', h: 210, s: 88, l: 52 },
  { name: '深海蓝', h: 220, s: 85, l: 42 },
  { name: '翡翠绿', h: 150, s: 80, l: 45 },
  { name: '森林绿', h: 130, s: 75, l: 38 },
  { name: '日落橙', h: 25, s: 90, l: 55 },
  { name: '烈焰红', h: 0, s: 85, l: 55 },
  { name: '薰衣紫', h: 265, s: 82, l: 58 },
  { name: '樱花粉', h: 340, s: 80, l: 60 },
]

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
      { id: 'theme', label: '主题', icon: '🎨' },
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
    presets: PRESETS,
    themeH: 210,
    themeS: 88,
    themeL: 52,
    _isCustom: false,
  }),
  computed: {
    mcpSafetyLabel() {
      const mode = this.serverConfig.mcp_safety_mode
      const map = { 'allow': '允许所有操作', 'confirm': '需要人工确认', 'safe': '完全禁止写操作' }
      return map[mode] || mode
    },
    currentBrandColor() {
      return `hsl(${this.themeH}deg ${this.themeS}% ${this.themeL}%)`
    },
    hueTrackBg() {
      const stops = []
      for (let i = 0; i <= 360; i += 60) {
        stops.push(`hsl(${i}deg ${this.themeS}% ${this.themeL}%)`)
      }
      return `linear-gradient(to right, ${stops.join(', ')})`
    },
  },
  async mounted() { 
    this.loadTheme()
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

    // Theme
    loadTheme() {
      try {
        const saved = localStorage.getItem('theme_hsl')
        if (saved) {
          const { h, s, l } = JSON.parse(saved)
          this.themeH = h; this.themeS = s; this.themeL = l
        }
        const custom = localStorage.getItem('theme_hsl_custom')
        if (custom === 'true') this._isCustom = true
      } catch(e) {}
    },
    applyTheme(h, s, l) {
      const root = document.documentElement
      root.style.setProperty('--brand-hue', h + 'deg')
      root.style.setProperty('--brand-sat', s + '%')
      root.style.setProperty('--brand-lit', l + '%')
      localStorage.setItem('theme_hsl', JSON.stringify({ h, s, l }))
    },
    applyPreset(p) {
      this.themeH = p.h; this.themeS = p.s; this.themeL = p.l
      this._isCustom = false
      localStorage.setItem('theme_hsl_custom', 'false')
      this.applyTheme(p.h, p.s, p.l)
    },
    applyCustom() {
      this._isCustom = true
      localStorage.setItem('theme_hsl_custom', 'true')
      this.applyTheme(this.themeH, this.themeS, this.themeL)
    },
    isPresetActive(p) {
      if (this._isCustom) return false
      return p.h === this.themeH && p.s === this.themeS && p.l === this.themeL
    },
    resetTheme() {
      this.themeH = 210; this.themeS = 88; this.themeL = 52
      this._isCustom = false
      localStorage.removeItem('theme_hsl')
      localStorage.removeItem('theme_hsl_custom')
      const root = document.documentElement
      root.style.removeProperty('--brand-hue')
      root.style.removeProperty('--brand-sat')
      root.style.removeProperty('--brand-lit')
    },
  },
}
</script>

<style scoped>
.settings-container { display: flex; height: 100%; gap: 24px; }

.settings-nav { width: 180px; display: flex; flex-direction: column; gap: 8px; flex-shrink: 0; }
.nav-btn { display: flex; align-items: center; gap: 10px; padding: 12px 16px; border: none; background: transparent; border-radius: 8px; cursor: pointer; text-align: left; font-size: 14px; color: var(--text-secondary); transition: .2s; }
.nav-btn:hover { background: var(--bg-hover); }
.nav-btn.active { background: var(--brand); color: var(--text-inverse); font-weight: 500; }

.settings-content { flex: 1; background: var(--bg-card); border-radius: 12px; box-shadow: var(--shadow-sm); padding: 24px; overflow-y: auto; }

.config-section h3 { margin: 0 0 20px; font-size: 18px; color: var(--text-primary); }
.info-banner { background: var(--bg-info); border: 1px solid hsl(var(--brand-hue) 50% 86%); color: var(--brand-hover); padding: 10px 16px; border-radius: 6px; font-size: 13px; margin-bottom: 24px; }

.form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
.form-item { display: flex; flex-direction: column; gap: 8px; }
.form-item.full { grid-column: span 2; }
.form-item label { font-size: 13px; color: var(--text-secondary); }
.form-item input, .form-item select { padding: 10px 12px; border: 1px solid var(--border-input); border-radius: 6px; background: var(--bg-table-header); font-size: 14px; }
.form-item input:disabled { color: var(--text-secondary); }

.checkbox-label { display: flex; align-items: center; gap: 10px; color: var(--text-primary) !important; cursor: pointer; }
.checkbox-label input { width: 18px; height: 18px; }

.settings-list { display: flex; flex-direction: column; }
.setting-row { display: flex; align-items: center; justify-content: space-between; padding: 16px 0; border-bottom: 1px solid var(--border-base); }
.setting-info { flex: 1; }
.setting-label { font-size: 15px; font-weight: 500; color: var(--text-primary); }
.setting-key { font-size: 12px; color: var(--text-tertiary); font-family: monospace; margin-top: 2px; }

.setting-control select { padding: 6px 12px; border-radius: 4px; border: 1px solid var(--border-strong); }
.input-group { display: flex; align-items: center; gap: 8px; }
.val-text { color: var(--brand); font-weight: 500; }
.edit-input { width: 120px; padding: 6px 10px; border: 1px solid var(--brand); border-radius: 4px; }

.btn-tool { display: flex; align-items: center; gap: 6px; padding: 8px 16px; border: 1px solid var(--border-strong); background: var(--bg-card); border-radius: 8px; cursor: pointer; font-size: 14px; transition: all 0.2s; }
.btn-tool:hover { border-color: var(--brand); color: var(--brand); }
.btn-tool.btn-primary { background: var(--brand); color: var(--text-inverse); border-color: var(--brand); }
.btn-tool.btn-primary:hover { opacity: 0.9; }

.btn-sm { padding: 6px 16px; border-radius: 6px; font-size: 13px; border: 1px solid var(--border-strong); background: var(--bg-card); cursor: pointer; }
.btn-sm.btn-primary { background: var(--brand); color: var(--text-inverse); border-color: var(--brand); }

.btn-edit-sm, .btn-save-sm, .btn-cancel-sm { padding: 4px 10px; border-radius: 4px; font-size: 12px; cursor: pointer; border: 1px solid var(--border-strong); background: var(--bg-card); }
.btn-save-sm { background: var(--brand); color: var(--text-inverse); border-color: var(--brand); }
.btn-edit-sm:hover { border-color: var(--brand); color: var(--brand); }

.section-header { display: flex; justify-content: space-between; align-items: baseline; }
.btn-refresh { border: none; background: transparent; color: var(--brand); cursor: pointer; font-size: 13px; }

.logs-wrapper { margin-top: 10px; }
.logs-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.logs-table th { text-align: left; padding: 12px; border-bottom: 2px solid var(--border-base); color: var(--text-secondary); font-weight: 500; }
.logs-table td { padding: 12px; border-bottom: 1px solid var(--border-base); color: var(--text-secondary); }
.log-fail { background: var(--bg-danger); }
.nowrap { white-space: nowrap; }
.proto-tag { background: var(--bg-hover); padding: 2px 6px; border-radius: 4px; font-size: 11px; }
.status-dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; margin-right: 4px; }
.status-dot.ok { background: var(--success); }
.status-dot.fail { background: var(--danger); }
.empty-logs { text-align: center; padding: 40px; color: var(--text-quaternary); }

.mount-list { border: 1px solid var(--border-base); border-radius: 8px; overflow: hidden; }
.mount-header, .mount-row { display: flex; padding: 12px 16px; border-bottom: 1px solid var(--border-base); align-items: center; }
.mount-header { background: var(--bg-table-header); font-weight: 600; color: var(--text-secondary); font-size: 13px; }
.mount-row:last-child { border-bottom: none; }
.mount-row.editing { background: var(--bg-info); }
.mh-name { width: 30%; }
.mh-path { flex: 1; color: var(--text-secondary); font-family: monospace; font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.mh-actions { width: 120px; text-align: right; display: flex; gap: 6px; justify-content: flex-end; }
.btn-danger { color: var(--danger); border-color: var(--danger); }
.mount-form { margin-top: 20px; padding: 20px; background: var(--bg-table-header); border-radius: 8px; border: 1px solid var(--border-base); }
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

/* Theme */
.theme-presets { margin-bottom: 28px; }
.preset-label { font-size: 14px; font-weight: 600; color: var(--text-primary); margin-bottom: 12px; }
.preset-grid { display: flex; gap: 12px; flex-wrap: wrap; }
.preset-btn { width: 36px; height: 36px; border-radius: 50%; border: 3px solid transparent; cursor: pointer; transition: .2s; outline: none; flex-shrink: 0; }
.preset-btn:hover { transform: scale(1.15); }
.preset-btn.active { border-color: var(--text-primary); box-shadow: 0 0 0 2px var(--bg-card); }

.theme-custom h4 { font-size: 14px; font-weight: 600; color: var(--text-primary); margin: 0 0 16px; }
.hsl-row { margin-bottom: 16px; }
.hsl-row label { display: flex; justify-content: space-between; font-size: 13px; color: var(--text-secondary); margin-bottom: 6px; }
.hsl-val { font-family: monospace; font-size: 12px; color: var(--text-tertiary); }
.slider-track { height: 24px; border-radius: 12px; position: relative; overflow: hidden; }
.hue-track { border-radius: 12px; }
.hsl-range { -webkit-appearance: none; appearance: none; width: 100%; height: 24px; background: transparent; cursor: pointer; position: absolute; top: 0; left: 0; margin: 0; }
.hsl-range::-webkit-slider-thumb { -webkit-appearance: none; appearance: none; width: 18px; height: 18px; border-radius: 50%; background: var(--bg-card); border: 2px solid var(--text-primary); cursor: pointer; box-shadow: 0 1px 4px rgba(0,0,0,.2); }
.hsl-range::-moz-range-thumb { width: 18px; height: 18px; border-radius: 50%; background: var(--bg-card); border: 2px solid var(--text-primary); cursor: pointer; box-shadow: 0 1px 4px rgba(0,0,0,.2); }

.theme-preview { margin-top: 20px; padding: 16px; background: var(--bg-page); border-radius: 8px; }
.preview-label { font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 10px; }
.preview-block { display: flex; align-items: center; gap: 16px; }
.preview-swatch { width: 48px; height: 48px; border-radius: 8px; border: 1px solid var(--border-base); flex-shrink: 0; }
.preview-samples { display: flex; gap: 8px; }
.sample { width: 28px; height: 28px; border-radius: 6px; border: 1px solid var(--border-base); }
.preview-code { font-family: monospace; font-size: 12px; color: var(--text-tertiary); margin-top: 8px; }
</style>
