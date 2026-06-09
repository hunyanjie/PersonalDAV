<template>
  <div>
    <div class="toolbar">
      <input v-model="query" placeholder="搜索联系人..." @input="onSearch" class="search-input" />
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
    <div v-else class="empty">暂无联系人</div>
  </div>
</template>

<script>
import api from '../api.js'
export default {
  data: () => ({ items: [], query: '' }),
  async mounted() { this.load() },
  methods: {
    async load() {
      try { this.items = await api.listContacts() } catch(e) {}
    },
    async onSearch() {
      if (!this.query.trim()) { this.load(); return }
      try { this.items = await api.searchContacts(this.query) } catch(e) {}
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
</style>
