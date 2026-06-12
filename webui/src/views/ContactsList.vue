<template>
  <div>
    <div class="toolbar">
      <input v-model="query" placeholder="搜索联系人..." @input="debounceSearch" class="search-input" />
      <label class="btn-primary btn-import">
        📥 导入 .vcf
        <input type="file" accept=".vcf,.vcard" @change="doImport" hidden />
      </label>
      <router-link to="/contacts/new" class="btn-primary">+ 新建</router-link>
    </div>
    <table v-if="items.length" class="data-table">
      <thead>
        <tr><th>姓名</th><th>邮箱</th><th>电话</th><th>分组</th><th>操作</th></tr>
      </thead>
      <tbody>
        <tr v-for="c in items" :key="c.uid">
          <td>{{ c.full_name }}</td>
          <td>{{ c.email }}</td>
          <td>{{ c.phone }}</td>
          <td>{{ c.groups }}</td>
            <td class="actions">
            <button class="btn-sm" @click="doExport(c)">导出</button>
            <router-link :to="`/contacts/${c.uid}/edit`" class="btn-sm">编辑</router-link>
            <button class="btn-sm btn-danger" @click="doDelete(c.uid)">删除</button>
          </td>
        </tr>
      </tbody>
    </table>
    <div v-else class="empty">{{ loading ? '加载中...' : '暂无联系人' }}</div>
    <div v-if="total > pageSize" class="pagination">
      <button :disabled="page === 0" @click="page--" class="btn-sm">&lt; 上一页</button>
      <span class="page-info">
        第 <input class="page-jump" v-model.number="pageInput" type="number" :min="1" :max="maxPage" @keyup.enter="jumpPage" />
        / {{ maxPage }} 页（共 {{ total }} 条）
      </span>
      <button :disabled="(page + 1) * pageSize >= total" @click="page++" class="btn-sm">下一页 &gt;</button>
      <select class="page-size" v-model.number="localPageSize" @change="changePageSize">
        <option :value="50">50 条/页</option>
        <option :value="100">100 条/页</option>
        <option :value="200">200 条/页</option>
        <option :value="500">500 条/页</option>
      </select>
    </div>
  </div>
</template>

<script>
import api from '../api.js'
export default {
  data: () => ({ items: [], query: '', page: 0, pageSize: 50, total: 0, loading: false, _timer: null, pageInput: 1, localPageSize: 50 }),
  computed: {
    maxPage() { return Math.max(1, Math.ceil(this.total / this.pageSize)) },
  },
  watch: { page() { this.pageInput = this.page + 1; this.load() } },
  async mounted() { this.load() },
  methods: {
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
        const vcard = await api.getContact(c.uid)
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
.toolbar { display: flex; gap: 12px; margin-bottom: 16px; }
.search-input { flex: 1; padding: 8px 12px; border: 1px solid var(--border-input); border-radius: 6px; font-size: 14px; }
.btn-primary { display: inline-flex; align-items: center; padding: 8px 16px; background: var(--brand); color: var(--text-inverse); text-decoration: none; border-radius: 6px; font-size: 14px; }
.btn-import { cursor: pointer; }
.data-table { width: 100%; background: var(--bg-card); border-radius: 8px; border-collapse: collapse; box-shadow: var(--shadow-sm); }
.data-table th, .data-table td { padding: 10px 16px; text-align: left; border-bottom: 1px solid var(--border-base); font-size: 14px; }
.data-table th { background: var(--bg-table-header); font-weight: 600; }
.actions { display: flex; gap: 8px; }
.btn-sm { padding: 4px 12px; border-radius: 4px; font-size: 13px; text-decoration: none; border: 1px solid var(--border-strong); background: var(--bg-card); cursor: pointer; }
.btn-danger { color: var(--danger-text); border-color: var(--danger-border); }
.empty { text-align: center; color: var(--text-tertiary); padding: 48px; font-size: 14px; }
.pagination { display: flex; align-items: center; justify-content: center; gap: 12px; margin-top: 16px; flex-wrap: wrap; }
.page-info { font-size: 14px; color: var(--text-secondary); display: flex; align-items: center; gap: 4px; }
.page-jump { width: 48px; padding: 2px 4px; border: 1px solid var(--border-strong); border-radius: 4px; text-align: center; font-size: 13px; }
.page-size { padding: 4px 8px; border: 1px solid var(--border-strong); border-radius: 4px; font-size: 13px; }
</style>
