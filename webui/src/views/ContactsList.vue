<template>
  <div>
    <div class="toolbar">
      <input v-model="query" placeholder="搜索联系人..." @input="debounceSearch" class="search-input" />
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
            <router-link :to="`/contacts/${c.uid}/edit`" class="btn-sm">编辑</router-link>
            <button class="btn-sm btn-danger" @click="doDelete(c.uid)">删除</button>
          </td>
        </tr>
      </tbody>
    </table>
    <div v-else class="empty">{{ loading ? '加载中...' : '暂无联系人' }}</div>
    <div v-if="total > pageSize" class="pagination">
      <button :disabled="page === 0" @click="page--" class="btn-sm">&lt; 上一页</button>
      <span class="page-info">{{ page + 1 }} / {{ Math.ceil(total / pageSize) }}</span>
      <button :disabled="(page + 1) * pageSize >= total" @click="page++" class="btn-sm">下一页 &gt;</button>
    </div>
  </div>
</template>

<script>
import api from '../api.js'
export default {
  data: () => ({ items: [], query: '', page: 0, pageSize: 50, total: 0, loading: false, _timer: null }),
  watch: { page() { this.load() } },
  async mounted() { this.load() },
  methods: {
    async load() {
      this.loading = true
      try {
        if (this.query.trim()) {
          this.items = await api.searchContacts(this.query)
          this.total = this.items.length
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
    async doDelete(uid) {
      if (!confirm('确认删除该联系人？')) return
      try { await api.deleteContact(uid); this.load() } catch(e) {}
    },
  },
}
</script>

<style scoped>
.toolbar { display: flex; gap: 12px; margin-bottom: 16px; }
.search-input { flex: 1; padding: 8px 12px; border: 1px solid #d9d9d9; border-radius: 6px; font-size: 14px; }
.btn-primary { display: inline-flex; align-items: center; padding: 8px 16px; background: #1677ff; color: #fff; text-decoration: none; border-radius: 6px; font-size: 14px; }
.data-table { width: 100%; background: #fff; border-radius: 8px; border-collapse: collapse; box-shadow: 0 1px 4px rgba(0,0,0,.06); }
.data-table th, .data-table td { padding: 10px 16px; text-align: left; border-bottom: 1px solid #f0f0f0; font-size: 14px; }
.data-table th { background: #fafafa; font-weight: 600; }
.actions { display: flex; gap: 8px; }
.btn-sm { padding: 4px 12px; border-radius: 4px; font-size: 13px; text-decoration: none; border: 1px solid #d9d9d9; background: #fff; cursor: pointer; }
.btn-danger { color: #cf1322; border-color: #ffa39e; }
.empty { text-align: center; color: #999; padding: 48px; font-size: 14px; }
.pagination { display: flex; align-items: center; justify-content: center; gap: 12px; margin-top: 16px; }
.page-info { font-size: 14px; color: #555; }
</style>
