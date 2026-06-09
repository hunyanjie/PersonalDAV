<template>
  <div>
    <div class="toolbar">
      <div class="breadcrumb">
        <a href="#" @click.prevent="cd('')">根目录</a>
        <span v-for="(seg, i) in breadcrumbs" :key="i">
          <span class="sep">/</span>
          <a href="#" @click.prevent="cd(seg.path)" v-if="i < breadcrumbs.length - 1">{{ seg.name }}</a>
          <span v-else>{{ seg.name }}</span>
        </span>
      </div>
      <span style="flex:1" />
      <button class="btn-plain" @click="showNewFolder = true">+ 目录</button>
      <label class="btn-primary upload-btn">
        上传
        <input type="file" multiple @change="doUpload" hidden />
      </label>
    </div>
    <div v-if="showNewFolder" class="inline-form">
      <input v-model="newFolderName" placeholder="目录名称" @keyup.enter="doMkdir" />
      <button class="btn-sm" @click="doMkdir">确定</button>
      <button class="btn-sm" @click="showNewFolder = false; newFolderName=''">取消</button>
    </div>
    <div v-if="renaming" class="inline-form">
      <input v-model="renameName" placeholder="新名称" @keyup.enter="doRename" />
      <button class="btn-sm" @click="doRename">确定</button>
      <button class="btn-sm" @click="renaming = null; renameName=''">取消</button>
    </div>
    <table v-if="items.length" class="data-table">
      <thead>
        <tr><th>名称</th><th>大小</th><th>修改时间</th><th>操作</th></tr>
      </thead>
      <tbody>
        <tr v-for="item in items" :key="item.path">
          <td>
            <a href="#" @click.prevent="item.is_dir ? cd(item.path) : null" class="file-link">
              {{ item.is_dir ? '📁' : '📄' }} {{ item.name }}
            </a>
          </td>
          <td>{{ item.is_dir ? '-' : formatSize(item.size) }}</td>
          <td>{{ formatDate(item.modified_at) }}</td>
          <td class="actions">
            <a v-if="!item.is_dir" :href="api.downloadUrl(item.path)" class="btn-sm">下载</a>
            <button class="btn-sm" @click="startRename(item)">重命名</button>
            <button class="btn-sm btn-danger" @click="doDelete(item)">删除</button>
          </td>
        </tr>
      </tbody>
    </table>
    <div v-else class="empty">空目录</div>
  </div>
</template>

<script>
import api from '../api.js'
export default {
  data: () => ({
    items: [], currentPath: '/', breadcrumbs: [],
    showNewFolder: false, newFolderName: '',
    renaming: null, renameName: '',
  }),
  async mounted() { this.load() },
  methods: {
    async load() {
      try {
        this.items = await api.listFiles(this.currentPath)
      } catch(e) { this.items = [] }
    },
    cd(path) {
      this.currentPath = path || '/'
      this.updateBreadcrumbs()
      this.load()
    },
    updateBreadcrumbs() {
      const parts = this.currentPath.replace(/^\/|\/$/g, '').split('/').filter(Boolean)
      const crumbs = []
      let acc = ''
      for (const p of parts) {
        acc += '/' + p
        crumbs.push({ name: p, path: acc })
      }
      this.breadcrumbs = crumbs
    },
    async doUpload(e) {
      const files = e.target.files
      for (const file of files) {
        try { await api.uploadFile(file, this.currentPath) } catch(e) {}
      }
      e.target.value = ''
      this.load()
    },
    async doMkdir() {
      if (!this.newFolderName.trim()) return
      try {
        await api.mkdir(this.currentPath.replace(/\/$/, '') + '/' + this.newFolderName.trim())
        this.newFolderName = ''; this.showNewFolder = false
        this.load()
      } catch(e) { alert('创建失败') }
    },
    startRename(item) {
      this.renaming = item; this.renameName = item.name
    },
    async doRename() {
      if (!this.renameName.trim() || !this.renaming) return
      try {
        await api.renameFile(this.renaming.path, this.renameName.trim())
        this.renaming = null; this.renameName = ''
        this.load()
      } catch(e) { alert('重命名失败') }
    },
    async doDelete(item) {
      if (!confirm(`确认删除 ${item.name}？`)) return
      try { await api.deleteFile(item.path); this.load() } catch(e) { alert('删除失败') }
    },
    formatSize(s) {
      if (s < 1024) return s + ' B'
      if (s < 1024*1024) return (s/1024).toFixed(1) + ' KB'
      return (s/1024/1024).toFixed(1) + ' MB'
    },
    formatDate(d) {
      if (!d) return ''
      return d.replace('T', ' ').substring(0, 16)
    },
  },
}
</script>

<style scoped>
.toolbar { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
.breadcrumb { flex: 1; font-size: 14px; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.breadcrumb a { color: #1677ff; text-decoration: none; }
.sep { color: #999; margin: 0 4px; }
.upload-btn { position: relative; display: inline-flex; align-items: center; padding: 8px 16px; background: #1677ff; color: #fff; border-radius: 6px; cursor: pointer; font-size: 14px; }
.btn-plain { padding: 6px 14px; border: 1px solid #d9d9d9; background: #fff; border-radius: 6px; cursor: pointer; font-size: 13px; }
.inline-form { display: flex; gap: 8px; align-items: center; margin-bottom: 12px; }
.inline-form input { flex: 1; padding: 6px 10px; border: 1px solid #d9d9d9; border-radius: 4px; font-size: 13px; }
.btn-sm { padding: 4px 12px; border-radius: 4px; font-size: 13px; text-decoration: none; border: 1px solid #d9d9d9; background: #fff; cursor: pointer; }
.data-table { width: 100%; background: #fff; border-radius: 8px; border-collapse: collapse; box-shadow: 0 1px 4px rgba(0,0,0,.06); }
.data-table th, .data-table td { padding: 10px 16px; text-align: left; border-bottom: 1px solid #f0f0f0; font-size: 14px; }
.data-table th { background: #fafafa; font-weight: 600; }
.file-link { color: #333; text-decoration: none; }
.actions { display: flex; gap: 8px; }
.btn-danger { color: #cf1322; border-color: #ffa39e; }
.empty { text-align: center; color: #999; padding: 48px; font-size: 14px; }
</style>
