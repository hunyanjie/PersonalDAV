<template>
  <div class="contacts-page">
    <div class="toolbar glass">
      <div class="search-box">
        <Search :size="18" class="search-icon" />
        <input v-model="query" placeholder="搜索联系人姓名、邮箱或电话..." @input="debounceSearch" class="search-input" />
      </div>
      <div class="toolbar-actions">
        <label class="btn-tool btn-import">
          <Upload :size="18" /> 导入 .vcf
          <input type="file" accept=".vcf,.vcard" @change="doImport" hidden />
        </label>
        <router-link to="/contacts/new" class="btn-tool btn-primary">
          <Plus :size="18" /> 新建联系人
        </router-link>
      </div>
    </div>

    <div class="list-wrapper glass">
      <table v-if="items.length" class="data-table">
        <thead>
          <tr>
            <th><div class="th-inner"><User :size="14" /> 姓名</div></th>
            <th><div class="th-inner"><Mail :size="14" /> 邮箱</div></th>
            <th><div class="th-inner"><Phone :size="14" /> 电话</div></th>
            <th><div class="th-inner"><Tag :size="14" /> 分组</div></th>
            <th class="col-actions">操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="c in items" :key="c.uid" class="contact-row">
            <td class="col-name">{{ c.full_name }}</td>
            <td class="col-email">{{ c.email || '-' }}</td>
            <td class="col-phone">{{ c.phone || '-' }}</td>
            <td>
              <div class="groups-list">
                <span v-for="g in splitGroups(c.groups)" :key="g" class="group-tag">{{ g }}</span>
              </div>
            </td>
            <td class="actions">
              <button class="btn-icon" @click="doExport(c)" title="导出 VCF"><ArrowDownToLine :size="16" /></button>
              <router-link :to="`/contacts/${c.uid}/edit`" class="btn-icon" title="编辑"><Pencil :size="16" /></router-link>
              <button class="btn-icon btn-danger" @click="doDelete(c.uid)" title="删除"><Trash2 :size="16" /></button>
            </td>
          </tr>
        </tbody>
      </table>
      <div v-else class="empty-state">
        <div class="empty-icon"><Users :size="48" /></div>
        <p>{{ loading ? '正在加载...' : '暂无联系人' }}</p>
      </div>
    </div>

    <div v-if="total > pageSize" class="pagination-bar glass">
      <div class="page-info">
        共 <strong>{{ total }}</strong> 条记录
      </div>
      <div class="page-controls">
        <button :disabled="page === 0" @click="page--" class="btn-page"><ChevronLeft :size="18" /></button>
        <div class="page-jump-box">
          <input class="page-input" v-model.number="pageInput" type="number" :min="1" :max="maxPage" @keyup.enter="jumpPage" />
          <span class="sep">/</span>
          <span>{{ maxPage }}</span>
        </div>
        <button :disabled="(page + 1) * pageSize >= total" @click="page++" class="btn-page"><ChevronRight :size="18" /></button>
      </div>
      <select class="page-size-select" v-model.number="localPageSize" @change="changePageSize">
        <option :value="50">50 条/页</option>
        <option :value="100">100 条/页</option>
        <option :value="200">200 条/页</option>
      </select>
    </div>
  </div>
</template>

<script>
import { 
  Search, Upload, Plus, User, Mail, Phone, Tag, 
  ArrowDownToLine, Pencil, Trash2, Users,
  ChevronLeft, ChevronRight
} from 'lucide-vue-next'
import api from '../api.js'

export default {
  components: { 
    Search, Upload, Plus, User, Mail, Phone, Tag, 
    ArrowDownToLine, Pencil, Trash2, Users,
    ChevronLeft, ChevronRight
  },
  data: () => ({ 
    items: [], query: '', page: 0, pageSize: 50, total: 0, 
    loading: false, _timer: null, pageInput: 1, localPageSize: 50 
  }),
  computed: {
    maxPage() { return Math.max(1, Math.ceil(this.total / this.pageSize)) },
  },
  watch: { 
    page() { this.pageInput = this.page + 1; this.load() } 
  },
  async mounted() { this.load() },
  methods: {
    splitGroups(g) {
      if (!g) return []
      return g.split(/[;；,，]/).filter(Boolean)
    },
    async load() {
      this.loading = true
      try {
        if (this.query.trim()) {
          const res = await api.searchContacts(this.query, this.page * this.pageSize, this.pageSize)
          this.items = res.items; this.total = res.total
        } else {
          const res = await api.listContacts(this.page * this.pageSize, this.pageSize)
          this.items = res.items; this.total = res.total
        }
      } catch(e) { this.items = []; this.total = 0 }
      finally { this.loading = false }
    },
    debounceSearch() {
      clearTimeout(this._timer)
      this._timer = setTimeout(() => { this.page = 0; this.load() }, 300)
    },
    changePageSize() {
      this.pageSize = this.localPageSize
      this.page = 0
    },
    jumpPage() {
      const p = Math.max(1, Math.min(this.maxPage, this.pageInput || 1)) - 1
      if (p !== this.page) this.page = p
    },
    async doImport(e) {
      const file = e.target.files[0]
      if (!file) return
      try {
        const text = await file.text()
        const blocks = text.split(/(?=BEGIN:VCARD)/).filter(Boolean)
        let ok = 0, fail = 0
        for (const block of blocks) {
          try { await api.createContact(block.trim()); ok++ }
          catch { fail++ }
        }
        alert(`导入完成：成功 ${ok} 条${fail ? `，失败 ${fail} 条` : ''}`)
        this.load()
      } catch(e) { alert('导入失败: ' + (e.message || e)) }
      e.target.value = ''
    },
    async doDelete(uid) {
      if (!confirm('确认删除该联系人？')) return
      try { await api.deleteContact(uid); this.load() } catch(e) {}
    },
    async doExport(c) {
      try {
        const res = await api.getContact(c.uid)
        const vcard = res.vcard || ''
        const blob = new Blob([vcard], { type: 'text/vcard;charset=utf-8' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url; a.download = `${c.full_name || '联系人'}.vcf`
        a.click(); URL.revokeObjectURL(url)
      } catch(e) { alert('导出失败: ' + (e.message || e)) }
    },
  },
}
</script>

<style scoped>
.contacts-page { height: 100%; display: flex; flex-direction: column; gap: 16px; }

.toolbar { 
  display: flex; 
  gap: 16px; 
  background: var(--bg-card); 
  padding: 12px 20px; 
  border-radius: var(--radius-lg); 
  box-shadow: var(--shadow-sm); 
  border: 1px solid var(--border-base);
  align-items: center;
}
.search-box { flex: 1; position: relative; }
.search-icon { position: absolute; left: 12px; top: 50%; transform: translateY(-50%); color: var(--text-tertiary); }
.search-input { 
  width: 100%; 
  padding: 10px 12px 10px 40px; 
  border: 1px solid var(--border-input); 
  border-radius: var(--radius-md); 
  font-size: 14px; 
  transition: all .2s;
  background: #fafafa;
}
.search-input:focus { border-color: var(--brand); background: white; box-shadow: 0 0 0 3px var(--brand-ring); outline: none; }

.toolbar-actions { display: flex; gap: 10px; }
.btn-tool { 
  display: flex; 
  align-items: center; 
  gap: 8px; 
  padding: 8px 16px; 
  border: 1px solid var(--border-strong); 
  background: var(--bg-card); 
  border-radius: var(--radius-md); 
  cursor: pointer; 
  font-size: 14px; 
  transition: all 0.2s; 
  text-decoration: none;
  color: var(--text-secondary);
}
.btn-tool:hover { border-color: var(--brand); color: var(--brand); background: var(--bg-info); }
.btn-tool.btn-primary { background: var(--brand); color: var(--text-inverse); border-color: var(--brand); }
.btn-tool.btn-primary:hover { opacity: 0.9; box-shadow: 0 4px 12px hsla(var(--brand-hue) var(--brand-sat) var(--brand-lit) / 0.2); }

.list-wrapper { 
  flex: 1; 
  background: var(--bg-card); 
  border-radius: var(--radius-lg); 
  box-shadow: var(--shadow-sm); 
  overflow-y: auto; 
  border: 1px solid var(--border-base);
}
.data-table { width: 100%; border-collapse: collapse; }
.data-table th { background: var(--bg-table-header); padding: 16px 20px; text-align: left; border-bottom: 1px solid var(--border-base); font-size: 13px; color: var(--text-secondary); }
.th-inner { display: flex; align-items: center; gap: 6px; }
.data-table td { padding: 16px 20px; border-bottom: 1px solid var(--border-base); font-size: 14px; color: var(--text-primary); }

.contact-row { transition: background .15s; }
.contact-row:hover { background: var(--bg-table-header); }
.col-name { font-weight: 600; }
.col-email, .col-phone { color: var(--text-secondary); }

.groups-list { display: flex; flex-wrap: wrap; gap: 6px; }
.group-tag { 
  background: var(--bg-info); 
  color: var(--brand); 
  padding: 2px 8px; 
  border-radius: 4px; 
  font-size: 12px; 
  font-weight: 500;
}

.actions { display: flex; gap: 4px; justify-content: flex-end; opacity: 0.4; transition: opacity .2s; }
.contact-row:hover .actions { opacity: 1; }
.btn-icon { width: 34px; height: 34px; display: inline-flex; align-items: center; justify-content: center; border: 1px solid transparent; border-radius: var(--radius-sm); background: transparent; cursor: pointer; text-decoration: none; color: var(--text-secondary); transition: all 0.2s; }
.btn-icon:hover { border-color: var(--border-base); background: white; color: var(--brand); box-shadow: var(--shadow-sm); }
.btn-icon.btn-danger:hover { color: var(--danger); background: var(--bg-danger); border-color: var(--danger-border); }

.empty-state { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 100px 0; color: var(--text-tertiary); }
.empty-icon { opacity: 0.3; margin-bottom: 16px; }

.pagination-bar { 
  display: flex; 
  align-items: center; 
  justify-content: space-between; 
  padding: 12px 24px; 
  background: var(--bg-card); 
  border-radius: var(--radius-lg); 
  box-shadow: var(--shadow-sm); 
  border: 1px solid var(--border-base);
}
.page-info { font-size: 13px; color: var(--text-secondary); }
.page-controls { display: flex; align-items: center; gap: 12px; }
.btn-page { width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; border: 1px solid var(--border-strong); border-radius: 50%; background: white; cursor: pointer; transition: .2s; }
.btn-page:hover:not(:disabled) { border-color: var(--brand); color: var(--brand); }
.btn-page:disabled { opacity: 0.3; cursor: not-allowed; }

.page-jump-box { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 500; }
.page-input { width: 44px; padding: 4px; border: 1px solid var(--border-input); border-radius: 4px; text-align: center; }
.page-size-select { padding: 6px 10px; border-radius: var(--radius-sm); border: 1px solid var(--border-strong); font-size: 13px; }
</style>
