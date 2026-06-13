<template>
  <div class="settings-container">
    <div class="settings-nav glass">
      <div class="nav-scroll-wrapper">
        <button v-for="s in sections" :key="s.id" 
          class="nav-btn" :class="{ active: activeSection === s.id }"
          @click="activeSection = s.id">
          <component :is="s.iconComp" :size="18" /> {{ s.label }}
        </button>
      </div>
    </div>

    <div class="settings-content glass">
      <!-- Transition wrapper for content -->
      <transition name="fade" mode="out-in">
        <div :key="activeSection">
          <!-- Server Settings -->
          <section v-if="activeSection === 'server'" class="config-section">
            <h3><Server :size="20" /> 服务器核心配置</h3>
            <div class="info-banner">
              <Info :size="16" />
              <span>只读信息，如需修改请编辑配置文件或在 GUI 中调整。</span>
            </div>
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
            <h3><FolderTree :size="20" /> 文件挂载点管理</h3>
            <div class="info-banner">
              <Info :size="16" />
              <span>每个挂载点将作为根目录下的一个虚拟目录显示。单挂载点时 / 直接显示文件内容。</span>
            </div>
            <div class="mount-list" v-if="mounts.length">
              <div class="mount-header">
                <span class="mh-name">挂载名称</span>
                <span class="mh-path hide-mobile">文件系统路径</span>
                <span class="mh-actions">操作</span>
              </div>
              <div v-for="m in mounts" :key="m.name" class="mount-row" :class="{ editing: editingMount === m.name }">
                <span class="mh-name">{{ m.name }}</span>
                <span class="mh-path hide-mobile">{{ m.path }}</span>
                <span class="mh-actions">
                  <button class="btn-edit-sm" @click="startEditMount(m)"><Pencil :size="12" /> <span class="hide-mobile">编辑</span></button>
                  <button class="btn-edit-sm btn-danger" @click="doDeleteMount(m.name)"><Trash2 :size="12" /> <span class="hide-mobile">删除</span></button>
                </span>
              </div>
            </div>
            <div v-else class="empty-logs">暂无挂载点</div>

            <!-- Add Mount Form -->
            <transition name="modal">
              <div class="mount-form glass no-transition" v-if="showMountForm">
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
                  <button class="btn-sm btn-primary" @click="saveMount" :disabled="!mountForm.name || !mountForm.path">保存挂载点</button>
                </div>
              </div>
            </transition>
            <button class="btn-tool btn-primary" @click="showAddMountForm" style="margin-top:12px">
              <Plus :size="18" /> 添加挂载点
            </button>
          </section>

          <!-- MCP Settings -->
          <section v-if="activeSection === 'mcp'" class="config-section">
            <h3><Bot :size="20" /> MCP (Model Context Protocol)</h3>
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
            <h3><Sliders :size="20" /> 可配置选项</h3>
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
              <h3><ShieldCheck :size="20" /> 鉴权审计日志</h3>
              <button class="btn-refresh" @click="loadLogs"><RotateCw :size="14" :class="{spinning: loading}" /> 刷新</button>
            </div>
            <div class="logs-wrapper">
              <table v-if="authLogs.length" class="logs-table">
                <thead><tr><th>时间</th><th>协议</th><th class="hide-mobile">详情</th><th>结果</th></tr></thead>
                <tbody>
                  <tr v-for="log in authLogs" :key="log.id" :class="{ 'log-fail': !log.success }">
                    <td class="nowrap">{{ log.time.replace('T', ' ').split(' ')[1].split('.')[0] }}</td>
                    <td><span class="proto-tag">{{ log.method }}</span></td>
                    <td :title="log.user_agent" class="hide-mobile">{{ log.detail }}</td>
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
              <h3><Terminal :size="20" /> 系统运行日志</h3>
              <button class="btn-refresh" @click="loadSystemLogs"><RotateCw :size="14" :class="{spinning: loading}" /> 刷新</button>
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
            <h3><Palette :size="20" /> 主题自定义</h3>
            <div class="info-banner">
              <Info :size="16" />
              <span>选择预设主题或自定义 HSL 调色板。修改后即时生效。</span>
            </div>

            <div class="theme-presets">
              <div class="preset-label">预设色板</div>
              <div class="preset-grid">
                <button v-for="p in presets" :key="p.name"
                  class="preset-btn no-transition"
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

              <div class="theme-preview glass">
                <div class="preview-label">品牌色预览</div>
                <div class="preview-block">
                  <div class="preview-swatch no-transition" :style="{ background: currentBrandColor }"></div>
                  <div class="preview-samples">
                    <div class="sample no-transition" :style="{ background: currentBrandColor }"></div>
                    <div class="sample sample-hover no-transition" :style="{ background: `hsl(${themeH}deg ${themeS}% ${Math.max(themeL-8,0)}%)` }"></div>
                    <div class="sample sample-soft no-transition" :style="{ background: `hsl(${themeH}deg ${Math.max(themeS-34,0)}% ${Math.min(themeL+43,100)}%)` }"></div>
                  </div>
                </div>
                <div class="preview-code">hsl({{ themeH }}deg {{ themeS }}% {{ themeL }}%)</div>
              </div>

              <button class="btn-sm" @click="resetTheme" style="margin-top:20px"><RotateCcw :size="14" /> 恢复默认蓝色</button>
            </div>
          </section>
        </div>
      </transition>
    </div>
  </div>
</template>

<script>
import { 
  Server, Sliders, FolderTree, Bot, ShieldCheck, 
  Terminal, Palette, Info, Pencil, Trash2, Plus, 
  RotateCw, RotateCcw
} from 'lucide-vue-next'
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
  components: { 
    Server, Sliders, FolderTree, Bot, ShieldCheck, 
    Terminal, Palette, Info, Pencil, Trash2, Plus, 
    RotateCw, RotateCcw
  },
  data: () => ({
    activeSection: 'server',
    sections: [
      { id: 'server', label: '核心配置', iconComp: 'Server' },
      { id: 'app', label: '通用选项', iconComp: 'Sliders' },
      { id: 'mounts', label: '文件挂载', iconComp: 'FolderTree' },
      { id: 'mcp', label: 'AI 服务', iconComp: 'Bot' },
      { id: 'logs', label: '安全审计', iconComp: 'ShieldCheck' },
      { id: 'syslogs', label: '系统日志', iconComp: 'Terminal' },
      { id: 'theme', label: '视觉主题', iconComp: 'Palette' },
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
    loading: false
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
      this.loading = true
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
      this.loading = false
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
    async loadTheme() {
      try {
        const saved = localStorage.getItem('theme_hsl')
        if (saved) {
          const { h, s, l } = JSON.parse(saved)
          this.themeH = h; this.themeS = s; this.themeL = l
        }
        const custom = localStorage.getItem('theme_hsl_custom')
        if (custom === 'true') this._isCustom = true
      } catch(e) {}
      try {
        const res = await api.getSetting('theme_hsl')
        if (res && res.value) {
          const { h, s, l } = JSON.parse(res.value)
          this.themeH = h; this.themeS = s; this.themeL = l
          this.applyTheme(h, s, l)
        }
      } catch (e) { /* 服务器无主题色设置时保持本地值 */ }
    },
    async applyTheme(h, s, l) {
      const root = document.documentElement
      root.style.setProperty('--brand-hue', h + 'deg')
      root.style.setProperty('--brand-sat', s + '%')
      root.style.setProperty('--brand-lit', l + '%')
      localStorage.setItem('theme_hsl', JSON.stringify({ h, s, l }))
      try {
        await api.updateSetting('theme_hsl', JSON.stringify({ h, s, l }))
      } catch (e) { /* 离线时仅保存本地 */ }
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
    async resetTheme() {
      this.themeH = 210; this.themeS = 88; this.themeL = 52
      this._isCustom = false
      localStorage.removeItem('theme_hsl')
      localStorage.removeItem('theme_hsl_custom')
      const root = document.documentElement
      root.style.removeProperty('--brand-hue')
      root.style.removeProperty('--brand-sat')
      root.style.removeProperty('--brand-lit')
      try {
        await api.updateSetting('theme_hsl', '')
      } catch (e) {}
    },
  },
}
</script>

<style scoped>
.settings-container { display: flex; height: 100%; gap: 24px; }

.settings-nav { width: 220px; display: flex; flex-direction: column; flex-shrink: 0; background: var(--bg-card); padding: 16px; border-radius: var(--radius-lg); border: 1px solid var(--border-base); box-shadow: var(--shadow-sm); height: fit-content; overflow: hidden; }
.nav-scroll-wrapper { display: flex; flex-direction: column; gap: 8px; }

.nav-btn { display: flex; align-items: center; gap: 12px; padding: 12px 16px; border: none; background: transparent; border-radius: var(--radius-md); cursor: pointer; text-align: left; font-size: 14px; font-weight: 500; color: var(--text-secondary); transition: .2s; white-space: nowrap; }
.nav-btn:hover { background: var(--bg-hover); color: var(--text-primary); }
.nav-btn.active { background: var(--brand); color: var(--text-inverse); box-shadow: 0 4px 12px hsla(var(--brand-hue) var(--brand-sat) var(--brand-lit) / 0.2); }

.settings-content { flex: 1; background: var(--bg-card); border-radius: var(--radius-lg); box-shadow: var(--shadow-sm); padding: 32px; overflow-y: auto; border: 1px solid var(--border-base); position: relative; }

.config-section h3 { margin: 0 0 24px; font-size: 20px; color: var(--text-primary); display: flex; align-items: center; gap: 10px; }
.info-banner { background: var(--bg-info); border: 1px solid hsla(var(--brand-hue), var(--brand-sat), var(--brand-lit), 0.1); color: var(--brand-hover); padding: 12px 16px; border-radius: var(--radius-md); font-size: 14px; margin-bottom: 32px; display: flex; align-items: center; gap: 10px; }

.form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
.form-item { display: flex; flex-direction: column; gap: 10px; }
.form-item.full { grid-column: span 2; }
.form-item label { font-size: 13px; font-weight: 600; color: var(--text-secondary); }
.form-item input, .form-item select { padding: 12px; border: 1px solid var(--border-input); border-radius: var(--radius-md); background: #fafafa; font-size: 14px; transition: all .2s; }
.form-item input:disabled { color: var(--text-secondary); cursor: not-allowed; }

.checkbox-label { display: flex; align-items: center; gap: 12px; color: var(--text-primary) !important; cursor: pointer; font-weight: 500; }
.checkbox-label input { width: 18px; height: 18px; border-radius: 4px; border: 2px solid var(--border-input); cursor: pointer; }

.settings-list { display: flex; flex-direction: column; }
.setting-row { display: flex; align-items: center; justify-content: space-between; padding: 20px 0; border-bottom: 1px solid var(--border-base); }
.setting-info { flex: 1; }
.setting-label { font-size: 15px; font-weight: 600; color: var(--text-primary); }
.setting-key { font-size: 12px; color: var(--text-tertiary); font-family: monospace; margin-top: 4px; opacity: 0.8; }

.setting-control select { padding: 8px 16px; border-radius: var(--radius-sm); border: 1px solid var(--border-strong); background: white; cursor: pointer; }
.input-group { display: flex; align-items: center; gap: 10px; }
.val-text { color: var(--brand); font-weight: 700; font-size: 15px; }
.edit-input { width: 140px; padding: 8px 12px; border: 1px solid var(--brand); border-radius: var(--radius-sm); outline: none; box-shadow: 0 0 0 3px var(--brand-ring); }

.btn-tool { display: flex; align-items: center; gap: 8px; padding: 10px 20px; border-radius: var(--radius-md); cursor: pointer; font-size: 14px; font-weight: 600; transition: all 0.2s; border: none; }
.btn-tool.btn-primary { background: var(--brand); color: var(--text-inverse); box-shadow: 0 4px 12px hsla(var(--brand-hue) var(--brand-sat) var(--brand-lit) / 0.2); }
.btn-tool.btn-primary:hover { transform: translateY(-1px); box-shadow: 0 6px 16px hsla(var(--brand-hue) var(--brand-sat) var(--brand-lit) / 0.3); }

.btn-sm { padding: 8px 20px; border-radius: var(--radius-sm); font-size: 13px; font-weight: 600; border: 1px solid var(--border-strong); background: white; cursor: pointer; transition: .2s; }
.btn-sm:hover { border-color: var(--brand); color: var(--brand); }
.btn-sm.btn-primary { background: var(--brand); color: var(--text-inverse); border: none; }

.btn-edit-sm, .btn-save-sm, .btn-cancel-sm { display: inline-flex; align-items: center; gap: 4px; padding: 6px 12px; border-radius: var(--radius-sm); font-size: 12px; font-weight: 600; cursor: pointer; border: 1px solid var(--border-strong); background: white; transition: .2s; }
.btn-save-sm { background: var(--brand); color: var(--text-inverse); border: none; }
.btn-edit-sm:hover { border-color: var(--brand); color: var(--brand); background: var(--bg-info); }

.section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
.btn-refresh { border: none; background: transparent; color: var(--brand); cursor: pointer; font-size: 14px; font-weight: 600; display: flex; align-items: center; gap: 6px; padding: 8px; border-radius: var(--radius-sm); transition: .2s; }
.btn-refresh:hover { background: var(--bg-info); }

.spinning { animation: rotate 1s linear infinite; }
@keyframes rotate { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }

.logs-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.logs-table th { text-align: left; padding: 14px; border-bottom: 2px solid var(--border-base); color: var(--text-secondary); font-weight: 600; background: #fafafa; }
.logs-table td { padding: 14px; border-bottom: 1px solid var(--border-base); color: var(--text-secondary); }
.log-fail { background: var(--bg-danger); }
.proto-tag { background: white; border: 1px solid var(--border-strong); padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; color: var(--text-secondary); }
.status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
.status-dot.ok { background: var(--success); box-shadow: 0 0 6px var(--success); }
.status-dot.fail { background: var(--danger); box-shadow: 0 0 6px var(--danger); }

.mount-list { border: 1px solid var(--border-base); border-radius: var(--radius-lg); overflow: hidden; box-shadow: var(--shadow-sm); }
.mount-header, .mount-row { display: flex; padding: 14px 20px; border-bottom: 1px solid var(--border-base); align-items: center; }
.mount-header { background: #fafafa; font-weight: 700; color: var(--text-secondary); font-size: 13px; }
.mount-row.editing { background: var(--bg-info); }
.mh-name { width: 30%; font-weight: 600; color: var(--text-primary); }
.mh-path { flex: 1; color: var(--text-secondary); font-family: monospace; font-size: 13px; opacity: 0.8; }
.mh-actions { width: 160px; text-align: right; display: flex; gap: 8px; justify-content: flex-end; }

.mount-form { margin-top: 24px; padding: 28px; background: #fafafa; border-radius: var(--radius-lg); border: 1px solid var(--border-base); }
.mount-form h4 { margin: 0 0 20px; font-size: 16px; }

.syslogs-wrapper { margin-top: 16px; background: #1a1a1a; color: #e0e0e0; padding: 20px; border-radius: var(--radius-lg); font-family: 'Fira Code', 'Courier New', monospace; font-size: 12px; height: 500px; overflow-y: auto; line-height: 1.6; border: 4px solid #2a2a2a; }
.syslog-line { margin-bottom: 4px; padding-bottom: 4px; border-bottom: 1px solid rgba(255,255,255,0.05); }
.sl-time { color: #666; margin-right: 12px; }
.sl-lv { font-weight: 700; margin-right: 12px; display: inline-block; min-width: 60px; }
.sl-name { color: #4fc3f7; margin-right: 12px; }
.lv-info .sl-lv { color: #4caf50; }
.lv-warning .sl-lv { color: #ffb300; }
.lv-error .sl-lv { color: #f44336; }

.theme-presets { margin-bottom: 32px; }
.preset-label { font-size: 15px; font-weight: 700; color: var(--text-primary); margin-bottom: 16px; }
.preset-grid { display: flex; gap: 14px; flex-wrap: wrap; }
.preset-btn { width: 40px; height: 40px; border-radius: 12px; border: 3px solid transparent; cursor: pointer; transition: transform 0.25s cubic-bezier(0.2, 0.8, 0.2, 1) !important; outline: none; }
.preset-btn:hover { transform: scale(1.15) rotate(5deg); }
.preset-btn.active { border-color: var(--text-primary); box-shadow: 0 0 0 4px var(--bg-info); }

.hsl-row { margin-bottom: 24px; }
.hsl-row label { display: flex; justify-content: space-between; font-size: 14px; font-weight: 600; color: var(--text-secondary); margin-bottom: 8px; }
.hsl-val { font-family: monospace; font-size: 14px; color: var(--brand); font-weight: 700; }
.slider-track { height: 28px; border-radius: 14px; position: relative; overflow: hidden; border: 1px solid rgba(0,0,0,0.05); }
.hsl-range { -webkit-appearance: none; appearance: none; width: 100%; height: 28px; background: transparent; cursor: pointer; position: absolute; top: 0; left: 0; margin: 0; z-index: 2; }
.hsl-range::-webkit-slider-thumb { -webkit-appearance: none; appearance: none; width: 22px; height: 22px; border-radius: 50%; background: white; border: 3px solid var(--text-primary); cursor: pointer; box-shadow: 0 2px 6px rgba(0,0,0,0.2); }

.theme-preview { margin-top: 32px; padding: 24px; background: #fafafa; border-radius: var(--radius-lg); border: 1px solid var(--border-base); }
.preview-label { font-size: 14px; font-weight: 700; color: var(--text-primary); margin-bottom: 16px; }
.preview-block { display: flex; align-items: center; gap: 24px; }
.preview-swatch { width: 64px; height: 64px; border-radius: var(--radius-md); border: 2px solid white; box-shadow: var(--shadow-md); flex-shrink: 0; }

@media (max-width: 768px) {
  .settings-container { flex-direction: column; gap: 16px; }
  .settings-nav { width: 100%; padding: 10px; border-radius: var(--radius-md); box-sizing: border-box; }
  .nav-scroll-wrapper { 
    display: flex;
    flex-direction: row; 
    flex-wrap: wrap;
    gap: 6px;
    justify-content: center;
    overflow-x: auto;
    scrollbar-width: none;
  }
  .nav-scroll-wrapper::-webkit-scrollbar { display: none; }
  .nav-btn { 
    padding: 8px 10px; 
    font-size: 12px; 
    background: #fafafa;
    border: 1px solid var(--border-base);
    flex: 0 0 auto;
    justify-content: center;
    min-width: 0;
    white-space: nowrap;
  }
  .nav-btn.active { background: var(--brand); border-color: var(--brand); }
  .settings-content { padding: 20px; }
  .form-grid { grid-template-columns: 1fr; gap: 16px; }
  .hide-mobile { display: none; }
  .mh-actions { width: 80px; }
}
@media (max-width: 400px) {
  .nav-btn { font-size: 11px; padding: 6px 8px; gap: 6px; }
  .nav-btn svg { width: 14px; height: 14px; }
}
</style>
