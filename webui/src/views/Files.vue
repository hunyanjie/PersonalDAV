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

    <div v-if="dragOver" class="dropzone-overlay"
      @dragenter.prevent @dragover.prevent @dragleave.prevent="dragOver = false"
      @drop.prevent="onDrop">
      <div class="dropzone-content">
        <div class="drop-icon">📤</div>
        <p>释放以上传文件</p>
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

    <!-- Preview Modal -->
    <div v-if="previewItem" class="inline-modal-overlay" @click.self="previewItem = null">
      <div class="preview-dialog">
        <div class="preview-header">
          <h3>{{ previewItem.name }}</h3>
          <button class="btn-close" @click="previewItem = null">&times;</button>
        </div>
        <div class="preview-body">
          <template v-if="previewSrc">
            <div v-if="_isImage" class="img-viewport" ref="imgViewport"
              @wheel.prevent="onImgWheel"
              @mousedown="onImgDown" @mousemove="onImgMove" @mouseup="onImgUp" @mouseleave="onImgUp">
              <img :src="previewSrc" :style="imgStyle" class="preview-img" :class="{ dragging: _isPanning }" draggable="false" />
              <div class="img-zoom-bar">
                <button @click="zoomOut" class="zoom-btn" title="缩小">−</button>
                <span class="zoom-label">{{ Math.round(_zoom * 100) }}%</span>
                <button @click="zoomIn" class="zoom-btn" title="放大">+</button>
                <button @click="zoomReset" class="zoom-btn" title="适应窗口">⟲</button>
              </div>
            </div>
            <iframe v-else :src="previewSrc" class="preview-iframe" />
          </template>
          <div v-else class="preview-error">{{ previewError || '不支持预览该文件类型' }}</div>
        </div>
        <div class="preview-footer">
          <a :href="api().downloadUrl(previewItem.path)" class="btn-sm btn-primary">下载</a>
          <button class="btn-sm" @click="previewItem = null">关闭</button>
        </div>
      </div>
    </div>

    <div class="files-list-wrapper">
      <table v-if="sortedItems.length" class="files-table">
        <thead>
          <tr>
            <th class="col-name sortable" @click="toggleSort('name')">
              名称
              <span v-if="sortField === 'name'" class="sort-indicator">{{ sortDir === 'asc' ? '▲' : '▼' }}</span>
            </th>
            <th class="col-size sortable" @click="toggleSort('size')">
              大小
              <span v-if="sortField === 'size'" class="sort-indicator">{{ sortDir === 'asc' ? '▲' : '▼' }}</span>
            </th>
            <th class="col-time sortable" @click="toggleSort('modified_at')">
              修改时间
              <span v-if="sortField === 'modified_at'" class="sort-indicator">{{ sortDir === 'asc' ? '▲' : '▼' }}</span>
            </th>
            <th class="col-actions">操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="item in sortedItems" :key="item.path" class="file-row">
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
                <button v-if="!item.is_dir && canPreview(item.name)" class="btn-icon" @click="doPreview(item)" title="预览">👁️</button>
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
const PREVIEW_EXTS = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg', 'pdf', 'txt', 'md', 'json', 'xml', 'yaml', 'yml', 'csv', 'log']
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
    sortField: 'name',
    sortDir: 'asc',
    previewItem: null,
    _previewSrc: null,
    _previewError: '',
    _previewBlobUrl: '',
    _isImage: false,
    _zoom: 1,
    _panX: 0,
    _panY: 0,
    _isPanning: false,
    _panStartX: 0,
    _panStartY: 0,
    _panStartPx: 0,
    _panStartPy: 0,
    dragOver: false,
  }),
  mounted() { 
    this.updateBreadcrumbs()
    this.load()
    document.addEventListener('dragenter', this.onDragEnter)
  },
  beforeUnmount() {
    document.removeEventListener('dragenter', this.onDragEnter)
  },
  computed: {
    sortedItems() {
      const arr = [...this.items]
      const dir = this.sortDir === 'asc' ? 1 : -1
      arr.sort((a, b) => {
        if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1
        if (this.sortField === 'size') return (a.size - b.size) * dir
        if (this.sortField === 'modified_at') {
          const da = new Date(a.modified_at || 0), db = new Date(b.modified_at || 0)
          return (da - db) * dir
        }
        return a.name.localeCompare(b.name, 'zh-CN') * dir
      })
      return arr
    },
    previewSrc() { return this._previewSrc },
    previewError() { return this._previewError },
    imgStyle() {
      if (!this._isImage) return {}
      return { transform: `translate(${this._panX}px, ${this._panY}px) scale(${this._zoom})` }
    },
  },
  methods: {
    api() { return api },
    toggleSort(field) {
      if (this.sortField === field) this.sortDir = this.sortDir === 'asc' ? 'desc' : 'asc'
      else { this.sortField = field; this.sortDir = 'asc' }
    },
    canPreview(name) {
      const ext = name.split('.').pop().toLowerCase()
      return PREVIEW_EXTS.includes(ext)
    },
    async doPreview(item) {
      this._previewSrc = null
      this._previewError = ''
      const ext = item.name.split('.').pop().toLowerCase()
      this._isImage = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg'].includes(ext)
      this._zoom = 1
      this._panX = 0
      this._panY = 0
      this._isPanning = false
      try {
        this._previewSrc = await api.previewFile(item.path)
      } catch (e) {
        this._previewError = '预览失败: ' + (e.message || e)
      }
      this.previewItem = item
    },
    zoomIn() { this._zoom = Math.min(4, +(this._zoom * 1.5).toFixed(2)) },
    zoomOut() { this._zoom = Math.max(0.25, +(this._zoom / 1.5).toFixed(2)) },
    zoomReset() { this._zoom = 1; this._panX = 0; this._panY = 0 },
    onImgWheel(e) {
      if (e.deltaY < 0) this.zoomIn(); else this.zoomOut()
    },
    onImgDown(e) {
      if (this._zoom <= 1) return
      this._isPanning = true
      this._panStartX = e.clientX
      this._panStartY = e.clientY
      this._panStartPx = this._panX
      this._panStartPy = this._panY
    },
    onImgMove(e) {
      if (!this._isPanning) return
      this._panX = this._panStartPx + (e.clientX - this._panStartX)
      this._panY = this._panStartPy + (e.clientY - this._panStartY)
    },
    onImgUp() { this._isPanning = false },
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
    },

    // Drag & Drop
    onDragEnter(e) {
      this.dragOver = true
    },
    async onDrop(e) {
      this.dragOver = false
      const files = e.dataTransfer.files
      if (!files.length) return
      this.loading = true
      for (const file of files) {
        try { await api.uploadFile(file, this.currentPath) } catch(e) {
          alert(`上传失败(${file.name}): ${e.message || e}`)
        }
      }
      this.load()
    },
  },
}
</script>

<style scoped>
.files-container { position: absolute; left: 24px; right: 24px; top: 24px; bottom: 24px; display: flex; flex-direction: column; }

.toolbar { display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px; gap: 16px; background: var(--bg-card); padding: 12px 20px; border-radius: 12px; box-shadow: var(--shadow-sm); }
.breadcrumb-bar { flex: 1; display: flex; align-items: center; min-width: 0; font-size: 15px; }
.btn-crumb { border: none; background: transparent; padding: 4px 8px; color: var(--brand); cursor: pointer; border-radius: 4px; transition: background 0.2s; white-space: nowrap; }
.btn-crumb:hover { background: var(--bg-info); }
.btn-crumb.is-last { color: var(--text-primary); font-weight: 600; cursor: default; pointer-events: none; }
.sep { color: var(--text-quaternary); margin: 0 4px; }

.toolbar-actions { display: flex; gap: 12px; }
.btn-tool { display: flex; align-items: center; gap: 6px; padding: 8px 16px; border: 1px solid var(--border-strong); background: var(--bg-card); border-radius: 8px; cursor: pointer; font-size: 14px; transition: all 0.2s; }
.btn-tool:hover { border-color: var(--brand); color: var(--brand); }
.btn-tool.btn-primary { background: var(--brand); color: var(--text-inverse); border-color: var(--brand); }
.btn-tool.btn-primary:hover { opacity: 0.9; }

.error-alert { background: var(--bg-danger); border: 1px solid var(--danger-border-strong); color: var(--danger-text); padding: 10px 16px; border-radius: 8px; margin-bottom: 16px; display: flex; align-items: center; gap: 12px; }
.btn-close { margin-left: auto; border: none; background: transparent; cursor: pointer; font-size: 18px; color: var(--text-tertiary); }

.files-list-wrapper { flex: 1; background: var(--bg-card); border-radius: 12px; box-shadow: var(--shadow-sm); overflow-y: auto; }
.files-table { width: 100%; border-collapse: collapse; table-layout: fixed; }
.files-table th { background: var(--bg-table-header); padding: 14px 20px; text-align: left; font-size: 14px; font-weight: 600; color: var(--text-secondary); border-bottom: 1px solid var(--border-base); user-select: none; }
.files-table th.sortable { cursor: pointer; }
.files-table th.sortable:hover { background: var(--bg-hover); }
.sort-indicator { font-size: 11px; margin-left: 4px; color: var(--brand); }
.files-table td { padding: 14px 20px; border-bottom: 1px solid var(--border-base); font-size: 14px; color: var(--text-primary); }

.col-name { width: 40%; }
.col-size { width: 12%; }
.col-time { width: 18%; }
.col-actions { width: 30%; text-align: right !important; }

.file-row:hover { background: var(--bg-table-header); }
.name-box { display: flex; align-items: center; gap: 10px; }
[class] .name-box { cursor: default; }
.name-box.dirs-clickable { cursor: default; }
.file-icon { font-size: 18px; }
.file-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.file-name.is-dir { color: var(--brand); font-weight: 500; }

.row-actions { display: flex; justify-content: flex-end; gap: 6px; }
.btn-icon { width: 32px; height: 32px; display: inline-flex; align-items: center; justify-content: center; border: 1px solid var(--border-strong); border-radius: 6px; background: var(--bg-card); cursor: pointer; text-decoration: none; font-size: 14px; transition: all 0.2s; }
.btn-icon:hover { border-color: var(--brand); background: var(--bg-info); }
.btn-icon.btn-danger:hover { border-color: var(--danger); background: var(--bg-danger); }

.empty-state, .loading-state { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 60px; color: var(--text-tertiary); }
.empty-icon { font-size: 48px; margin-bottom: 16px; opacity: 0.3; }

.inline-modal-overlay { position: fixed; inset: 0; z-index: 1000; background: rgba(0,0,0,0.3); display: flex; align-items: center; justify-content: center; backdrop-filter: blur(2px); }
.inline-dialog { background: var(--bg-card); width: 400px; padding: 24px; border-radius: 12px; box-shadow: var(--shadow-lg); }
.inline-dialog h3 { margin: 0 0 16px; font-size: 16px; }
.inline-dialog input { width: 100%; padding: 10px 12px; border: 1px solid var(--border-input); border-radius: 6px; margin-bottom: 20px; box-sizing: border-box; }
.dialog-actions { display: flex; justify-content: flex-end; gap: 12px; }
.btn-sm { padding: 6px 16px; border-radius: 6px; font-size: 13px; border: 1px solid var(--border-strong); background: var(--bg-card); cursor: pointer; }
.btn-sm.btn-primary { background: var(--brand); color: var(--text-inverse); border-color: var(--brand); }
.btn-danger { color: var(--danger-text); border-color: var(--danger-border); }

.preview-dialog { background: var(--bg-card); width: 80vw; height: 80vh; max-width: 960px; border-radius: 12px; display: flex; flex-direction: column; overflow: hidden; box-shadow: var(--shadow-lg); }
.preview-header { display: flex; justify-content: space-between; align-items: center; padding: 16px 20px; border-bottom: 1px solid var(--border-base); }
.preview-header h3 { margin: 0; font-size: 16px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.preview-body { flex: 1; overflow: hidden; background: var(--bg-page); }
.preview-iframe { width: 100%; height: 100%; border: none; }
.preview-error { display: flex; align-items: center; justify-content: center; height: 100%; color: var(--text-tertiary); font-size: 16px; }
.preview-footer { display: flex; justify-content: flex-end; gap: 8px; padding: 12px 20px; border-top: 1px solid var(--border-base); }

.img-viewport { width: 100%; height: 100%; overflow: hidden; display: flex; align-items: center; justify-content: center; background: var(--bg-page); position: relative; }
.preview-img { max-width: 100%; max-height: 100%; cursor: grab; user-select: none; transition: transform 0.12s; }
.preview-img.dragging { cursor: grabbing; transition: none; }
.img-zoom-bar { position: absolute; bottom: 16px; left: 50%; transform: translateX(-50%); background: rgba(0,0,0,.6); border-radius: 8px; display: flex; align-items: center; gap: 2px; padding: 4px; backdrop-filter: blur(4px); }
.zoom-btn { border: none; background: transparent; color: #fff; width: 32px; height: 32px; border-radius: 6px; cursor: pointer; font-size: 16px; display: flex; align-items: center; justify-content: center; }
.zoom-btn:hover { background: rgba(255,255,255,.15); }
.zoom-label { color: #fff; font-size: 12px; min-width: 40px; text-align: center; }

.dropzone-overlay { position: fixed; inset: 0; z-index: 2000; background: hsl(var(--brand-hue) var(--brand-sat) var(--brand-lit) / 0.08); display: flex; align-items: center; justify-content: center; backdrop-filter: blur(4px); }
.dropzone-content { background: var(--bg-card); border: 3px dashed var(--brand); border-radius: 20px; padding: 60px 80px; text-align: center; box-shadow: 0 8px 32px hsl(var(--brand-hue) var(--brand-sat) var(--brand-lit) / 0.2); }
.drop-icon { font-size: 64px; margin-bottom: 16px; }
.dropzone-content p { font-size: 20px; color: var(--brand); font-weight: 500; margin: 0; }
</style>
