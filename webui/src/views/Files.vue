<template>
  <div class="files-container">
    <div class="toolbar">
      <div class="breadcrumb-bar">
        <button class="btn-crumb" @click="cd('')">根目录</button>
        <div v-for="(seg, i) in breadcrumbs" :key="i" class="crumb-item">
          <span class="sep">/</span>
          <button class="btn-crumb" :class="{ 'is-last': i === breadcrumbs.length - 1 }" @click="cd(seg.path)">
            {{ seg.name }}
          </button>
        </div>
      </div>
      <div class="toolbar-actions">
        <button class="btn-tool" @click="showNewFolder = true">
          <span class="icon">📁</span>+ 目录
        </button>
        <label class="btn-tool btn-primary">
          <span class="icon">📤</span> 上传
          <input type="file" multiple @change="doUpload" hidden />
        </label>
        <button class="btn-tool" @click="load">
          <span class="icon">🔄</span> 刷新
        </button>
      </div>
    </div>

    <div v-if="errorMsg" class="error-alert">
      <span class="icon">⚠️</span> {{ errorMsg }}
      <button class="btn-close" @click="errorMsg = ''">&times;</button>
    </div>

    <div v-if="showNewFolder" class="inline-modal-overlay" @click.self="showNewFolder = false">
      <div class="inline-dialog">
        <h3>创建新目录</h3>
        <input v-model="newFolderName" placeholder="请输入目录名称" @keyup.enter="doMkdir" autofocus />
        <div class="dialog-actions">
          <button class="btn-sm" @click="showNewFolder = false">取消</button>
          <button class="btn-sm btn-primary" @click="doMkdir">创建</button>
        </div>
      </div>
    </div>

    <div v-if="renaming" class="inline-modal-overlay" @click.self="renaming = null">
      <div class="inline-dialog">
        <h3>重命名</h3>
        <input v-model="renameName" placeholder="请输入新名称" @keyup.enter="doRename" autofocus />
        <div class="dialog-actions">
          <button class="btn-sm" @click="renaming = null">取消</button>
          <button class="btn-sm btn-primary" @click="doRename">重命名</button>
        </div>
      </div>
    </div>

    <div class="files-list-wrapper">
      <table v-if="items.length" class="files-table">
        <thead>
          <tr>
            <th>名称</th>
            <th>大小</th>
            <th>修改时间</th>
            <th class="col-actions">操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="item in items" :key="item.path" class="file-row">
            <td class="col-name">
              <div class="name-box" @click="item.is_dir ? cd(item.path) : null">
                <span class="file-icon">{{ item.is_dir ? '📂' : getFileIcon(item.name) }}</span>
                <span class="file-name" :class="{ 'is-dir': item.is_dir }">{{ item.name }}</span>
              </div>
            </td>
            <td class="col-size">{{ item.is_dir ? '-' : formatSize(item.size) }}</td>
            <td class="col-time">{{ formatDate(item.modified_at) }}</td>
            <td class="col-actions">
              <div class="row-actions">
                <a v-if="!item.is_dir" :href="api().downloadUrl(item.path)" class="btn-icon" title="下载">📥</a>
                <button class="btn-icon" @click="startRename(item)" title="重命名">✏️</button>
                <button class="btn-icon btn-danger" @click="doDelete(item)" title="删除">🗑️</button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
      <div v-else-if="!loading" class="empty-state">
        <div class="empty-icon">📁</div>
        <p>暂无文件</p>
      </div>
      <div v-if="loading" class="loading-state">正在加载文件列表...</div>
    </div>
  </div>
</template>

<script>
import api from '../api.js'
export default {
  data: () => ({
    items: [], 
    currentPath: '/', 
    breadcrumbs: [],
    showNewFolder: false, 
    newFolderName: '',
    renaming: null, 
    renameName: '',
    loading: false,
    errorMsg: '',
  }),
  async mounted() { 
    this.updateBreadcrumbs()
    await this.load() 
  },
  methods: {
    api() { return api },
    async load() {
      this.loading = true
      this.errorMsg = ''
      try {
        const res = await api.listFiles(this.currentPath)
        if (Array.isArray(res)) {
          this.items = res
        } else {
          this.items = []
          this.errorMsg = '获取文件列表失败：服务器返回格式错误'
        }
      } catch(e) { 
        this.items = [] 
        this.errorMsg = '加载文件失败：' + (e.message || '未知错误')
      } finally {
        this.loading = false
      }
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
      if (!files.length) return
      this.loading = true
      for (const file of files) {
        try { await api.uploadFile(file, this.currentPath) } catch(e) {
          alert(`上传失败(${file.name}): ${e.message || e}`)
        }
      }
      e.target.value = ''
      this.load()
    },
    async doMkdir() {
      const name = this.newFolderName.trim()
      if (!name) return
      try {
        await api.mkdir(this.currentPath.replace(/\/$/, '') + '/' + name)
        this.newFolderName = ''
        this.showNewFolder = false
        this.load()
      } catch(e) { alert('创建失败：' + (e.message || e)) }
    },
    startRename(item) {
      this.renaming = item; this.renameName = item.name
    },
    async doRename() {
      const newName = this.renameName.trim()
      if (!newName || !this.renaming) return
      try {
        await api.renameFile(this.renaming.path, newName)
        this.renaming = null; this.renameName = ''
        this.load()
      } catch(e) { alert('重命名失败：' + (e.message || e)) }
    },
    async doDelete(item) {
      if (!confirm(`确认删除 ${item.name}？\n此操作无法撤销。`)) return
      try { 
        await api.deleteFile(item.path)
        this.load() 
      } catch(e) { alert('删除失败：' + (e.message || e)) }
    },
    formatSize(s) {
      if (!s) return '0 B'
      if (s < 1024) return s + ' B'
      if (s < 1024*1024) return (s/1024).toFixed(1) + ' KB'
      if (s < 1024*1024*1024) return (s/1024/1024).toFixed(1) + ' MB'
      return (s/1024/1024/1024).toFixed(1) + ' GB'
    },
    formatDate(d) {
      if (!d) return ''
      return d.replace('T', ' ').substring(0, 16)
    },
    getFileIcon(name) {
      const ext = name.split('.').pop().toLowerCase()
      const icons = {
        pdf: '📄', ics: '📅', vcf: '👤', txt: '📝', 
        jpg: '🖼️', jpeg: '🖼️', png: '🖼️', gif: '🖼️',
        zip: '📦', rar: '📦', '7z': '📦',
        mp3: '🎵', mp4: '🎬',
      }
      return icons[ext] || '📄'
    }
  },
}
</script>

<style scoped>
.files-container { display: flex; flex-direction: column; height: 100%; }

.toolbar { display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px; gap: 16px; background: #fff; padding: 12px 20px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.04); }
.breadcrumb-bar { flex: 1; display: flex; align-items: center; min-width: 0; font-size: 15px; }
.btn-crumb { border: none; background: transparent; padding: 4px 8px; color: #1677ff; cursor: pointer; border-radius: 4px; transition: background 0.2s; white-space: nowrap; }
.btn-crumb:hover { background: #e6f4ff; }
.btn-crumb.is-last { color: #333; font-weight: 600; cursor: default; pointer-events: none; }
.sep { color: #ccc; margin: 0 4px; }

.toolbar-actions { display: flex; gap: 12px; }
.btn-tool { display: flex; align-items: center; gap: 6px; padding: 8px 16px; border: 1px solid #d9d9d9; background: #fff; border-radius: 8px; cursor: pointer; font-size: 14px; transition: all 0.2s; }
.btn-tool:hover { border-color: #1677ff; color: #1677ff; }
.btn-tool.btn-primary { background: #1677ff; color: #fff; border-color: #1677ff; }
.btn-tool.btn-primary:hover { opacity: 0.9; }

.error-alert { background: #fff2f0; border: 1px solid #ffccc7; color: #cf1322; padding: 10px 16px; border-radius: 8px; margin-bottom: 16px; display: flex; align-items: center; gap: 12px; }
.btn-close { margin-left: auto; border: none; background: transparent; cursor: pointer; font-size: 18px; color: #999; }

.files-list-wrapper { flex: 1; background: #fff; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.04); overflow: hidden; display: flex; flex-direction: column; }
.files-table { width: 100%; border-collapse: collapse; table-layout: fixed; }
.files-table th { background: #fafafa; padding: 14px 20px; text-align: left; font-size: 14px; font-weight: 600; color: #666; border-bottom: 1px solid #f0f0f0; }
.files-table td { padding: 14px 20px; border-bottom: 1px solid #f0f0f0; font-size: 14px; color: #333; }

.col-name { width: 45%; }
.col-size { width: 15%; }
.col-time { width: 20%; }
.col-actions { width: 20%; text-align: right !important; }

.file-row:hover { background: #fafafa; }
.name-box { display: flex; align-items: center; gap: 10px; cursor: pointer; }
.file-icon { font-size: 18px; }
.file-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.file-name.is-dir { color: #1677ff; font-weight: 500; }

.row-actions { display: flex; justify-content: flex-end; gap: 8px; }
.btn-icon { width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; border: 1px solid #d9d9d9; border-radius: 6px; background: #fff; cursor: pointer; text-decoration: none; font-size: 14px; transition: all 0.2s; }
.btn-icon:hover { border-color: #1677ff; background: #e6f4ff; }
.btn-icon.btn-danger:hover { border-color: #ff4d4f; background: #fff2f0; }

.empty-state, .loading-state { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 60px; color: #999; }
.empty-icon { font-size: 48px; margin-bottom: 16px; opacity: 0.3; }

.inline-modal-overlay { position: fixed; inset: 0; z-index: 1000; background: rgba(0,0,0,0.3); display: flex; align-items: center; justify-content: center; backdrop-filter: blur(2px); }
.inline-dialog { background: #fff; width: 400px; padding: 24px; border-radius: 12px; box-shadow: 0 8px 24px rgba(0,0,0,0.15); }
.inline-dialog h3 { margin: 0 0 16px; font-size: 16px; }
.inline-dialog input { width: 100%; padding: 10px 12px; border: 1px solid #d9d9d9; border-radius: 6px; margin-bottom: 20px; box-sizing: border-box; }
.dialog-actions { display: flex; justify-content: flex-end; gap: 12px; }
.btn-sm { padding: 6px 16px; border-radius: 6px; font-size: 13px; border: 1px solid #d9d9d9; background: #fff; cursor: pointer; }
</style>
