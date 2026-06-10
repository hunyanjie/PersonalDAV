<template>
  <div class="settings-page">
    <section class="section">
      <h3>服务器配置</h3>
      <div class="field">
        <label>监听主机</label>
        <input v-model="serverConfig.host" disabled />
      </div>
      <div class="field">
        <label>端口</label>
        <input v-model.number="serverConfig.port" disabled />
      </div>
      <div class="field">
        <label>日志级别</label>
        <input v-model="serverConfig.log_level" disabled />
      </div>
      <div class="field">
        <label>数据文件路径</label>
        <input v-model="serverConfig.db_path" disabled />
      </div>
      <div class="field">
        <label>WebDAV 根目录</label>
        <input v-model="serverConfig.dav_root" disabled />
      </div>
    </section>

    <section class="section">
      <h3>MCP 配置</h3>
      <div class="field">
        <label>启用 MCP</label>
        <input type="checkbox" :checked="serverConfig.mcp_enabled" disabled />
      </div>
      <div class="field">
        <label>MCP 端口</label>
        <input v-model.number="serverConfig.mcp_port" disabled />
      </div>
      <div class="field">
        <label>安全模式</label>
        <input v-model="serverConfig.mcp_safety_mode" disabled />
      </div>
      <div class="field">
        <label>只读模式</label>
        <input type="checkbox" :checked="serverConfig.mcp_readonly" disabled />
      </div>
    </section>

    <section class="section">
      <h3>设置项</h3>
      <table class="data-table" v-if="Object.keys(settings).length">
        <thead><tr><th>键</th><th>值</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="(v, k) in settings" :key="k">
            <td>{{ k }}</td>
            <td>
              <input v-if="editingKey === k" v-model="editValue" class="inline-input" />
              <span v-else>{{ v }}</span>
            </td>
            <td class="actions">
              <button v-if="editingKey === k" class="btn-sm" @click="doUpdate(k)">保存</button>
              <button v-if="editingKey === k" class="btn-sm" @click="editingKey = null">取消</button>
              <button v-else class="btn-sm" @click="startEdit(k, v)">编辑</button>
            </td>
          </tr>
        </tbody>
      </table>
      <div v-else class="empty">暂无设置</div>
    </section>

        <section class="section">
      <h3>鉴权日志（最近 20 条）</h3>
      <table class="data-table" v-if="authLogs.length">
        <thead><tr><th>时间</th><th>协议</th><th>客户端</th><th>结果</th><th>指纹</th></tr></thead>
        <tbody>
          <tr v-for="log in authLogs" :key="log.id">
            <td>{{ log.time }}</td>
            <td>{{ log.method }}</td>
            <td :title="`UA: ${log.user_agent || '-'}`">{{ log.detail }}</td>
            <td>{{ log.success ? '成功' : '失败' }}</td>
            <td :title="`UA: ${log.user_agent || '-'}`">{{ log.fingerprint ? log.fingerprint.substring(0, 8) : '-' }}</td>
          </tr>
        </tbody>
      </table>
      <div v-else class="empty">暂无日志</div>
    </section>
  </div>
</template>

<script>
import api from '../api.js'
export default {
  data: () => ({
    serverConfig: {},
    settings: {},
    authLogs: [],
    editingKey: null,
    editValue: '',
  }),
  async mounted() { await this.load() },
  methods: {
    async load() {
      try { this.serverConfig = await api.serverConfig() } catch(e) {}
      try { this.settings = await api.listSettings() } catch(e) {}
      try { this.authLogs = await api.authLogs(20) } catch(e) {}
    },
    startEdit(key, value) {
      this.editingKey = key; this.editValue = value
    },
    async doUpdate(key) {
      try {
        await api.updateSetting(key, this.editValue)
        this.settings[key] = this.editValue
        this.editingKey = null
      } catch(e) { alert('更新失败') }
    },
  },
}
</script>

<style scoped>
.settings-page { display: flex; flex-direction: column; gap: 24px; }
.section { background: #fff; border-radius: 8px; padding: 20px; box-shadow: 0 1px 4px rgba(0,0,0,.06); }
.section h3 { margin: 0 0 16px; font-size: 16px; }
.field { display: flex; align-items: center; gap: 12px; margin-bottom: 10px; }
.field label { font-size: 14px; color: #555; min-width: 100px; }
.field input:not([type="checkbox"]) { flex: 1; padding: 6px 10px; border: 1px solid #d9d9d9; border-radius: 4px; font-size: 13px; max-width: 300px; }
.field input:disabled { background: #f5f5f5; color: #999; }
.data-table { width: 100%; border-collapse: collapse; font-size: 14px; }
.data-table th, .data-table td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #f0f0f0; }
.data-table th { background: #fafafa; font-weight: 600; }
.inline-input { padding: 4px 8px; border: 1px solid #d9d9d9; border-radius: 4px; width: 200px; }
.actions { display: flex; gap: 6px; }
.btn-sm { padding: 4px 12px; border-radius: 4px; font-size: 13px; text-decoration: none; border: 1px solid #d9d9d9; background: #fff; cursor: pointer; }
.empty { text-align: center; color: #999; padding: 24px; font-size: 14px; }
</style>
