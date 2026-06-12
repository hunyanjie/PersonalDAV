<template>
  <div class="files-container">
    <div class="toolbar glass">
      <div class="breadcrumb-bar">
        <button class="btn-crumb" @click="cd('')"><Home :size="16" /> 根目录</button>
        <div v-for="(seg, i) in breadcrumbs" :key="i" class="crumb-item">
          <ChevronRight :size="14" class="sep" />
          <button class="btn-crumb" :class="{ 'is-last': i === breadcrumbs.length - 1 }" @click="cd(seg.path)">
            {{ seg.name }}
          </button>
        </div>
      </div>
      <div class="toolbar-actions">
        <button class="btn-tool" @click="showNewFolder = true">
          <FolderPlus :size="18" /> 目录
        </button>
        <label class="btn-tool btn-primary">
          <Upload :size="18" /> 上传
          <input type="file" multiple @change="doUpload" hidden />
        </label>
        <button class="btn-tool" @click="load">
          <RotateCw :size="18" :class="{ 'spinning': loading }" />
        </button>
      </div>
    </div>

    <div v-if="errorMsg" class="error-alert">
      <AlertCircle :size="18" /> {{ errorMsg }}
      <button class="btn-close" @click="errorMsg = ''">&times;</button>
    </div>

    <!-- Modals (rest of logic same, just styling updates) -->
    <div v-if="showNewFolder" class="inline-modal-overlay" @click.self="showNewFolder = false">
      <div class="inline-dialog glass">
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
      <div class="dropzone-content glass">
        <div class="drop-icon"><Upload :size="48" /></div>
        <p>释放以上传文件</p>
      </div>
    </div>

    <div v-if="renaming" class="inline-modal-overlay" @click.self="renaming = null">
      <div class="inline-dialog glass">
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
      <div class="preview-dialog glass">
        <div class="preview-header">
          <h3>{{ previewItem.name }}</h3>
          <button class="btn-close-preview" @click="previewItem = null"><X :size="20" /></button>
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
                <button @click="zoomReset" class="zoom-btn" title="适应窗口"><RefreshCw :size="14" /></button>
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

    <div class="files-list-wrapper glass">
      <table v-if="sortedItems.length" class="files-table">
        <thead>
          <tr>
            <th class="col-name sortable" @click="toggleSort('name')">
              名称
              <span v-if="sortField === 'name'" class="sort-indicator">
                <ChevronUp v-if="sortDir === 'asc'" :size="12" />
                <ChevronDown v-else :size="12" />
              </span>
            </th>
            <th class="col-size sortable" @click="toggleSort('size')">
              大小
              <span v-if="sortField === 'size'" class="sort-indicator">
                <ChevronUp v-if="sortDir === 'asc'" :size="12" />
                <ChevronDown v-else :size="12" />
              </span>
            </th>
            <th class="col-time sortable" @click="toggleSort('modified_at')">
              修改时间
              <span v-if="sortField === 'modified_at'" class="sort-indicator">
                <ChevronUp v-if="sortDir === 'asc'" :size="12" />
                <ChevronDown v-else :size="12" />
              </span>
            </th>
            <th class="col-actions">操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="item in sortedItems" :key="item.path" class="file-row">
            <td class="col-name">
              <div class="name-box" @click="item.is_dir ? cd(item.path) : null" :class="{ 'is-clickable': item.is_dir }">
                <component :is="getFileIconComponent(item)" class="file-icon-comp" :class="{ 'dir-icon': item.is_dir }" :size="20" />
                <span class="file-name" :class="{ 'is-dir': item.is_dir }">{{ item.name }}</span>
              </div>
            </td>
            <td class="col-size">{{ item.is_dir ? '-' : formatSize(item.size) }}</td>
            <td class="col-time">{{ formatDate(item.modified_at) }}</td>
            <td class="col-actions">
              <div class="row-actions">
                <button v-if="!item.is_dir && canPreview(item.name)" class="btn-icon" @click="doPreview(item)" title="预览"><Eye :size="16" /></button>
                <a v-if="!item.is_dir" :href="api().downloadUrl(item.path)" class="btn-icon" title="下载"><Download :size="16" /></a>
                <button class="btn-icon" @click="startRename(item)" title="重命名"><Pencil :size="16" /></button>
                <button class="btn-icon btn-danger" @click="doDelete(item)" title="删除"><Trash2 :size="16" /></button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
      <div v-else-if="!loading" class="empty-state">
        <div class="empty-icon"><FolderOpen :size="48" /></div>
        <p>此目录空空如也</p>
      </div>
      <div v-if="loading && !items.length" class="loading-state">正在加载文件列表...</div>
    </div>
  </div>
</template>

<script>
import { 
  Home, ChevronRight, ChevronUp, ChevronDown, FolderPlus, Upload, 
  RotateCw, AlertCircle, X, Eye, Download, Pencil, Trash2, 
  File, FileImage, FileText, FileArchive, FileMusic, FileVideo, 
  FileQuestion, Folder, FolderOpen, RefreshCw
} from 'lucide-vue-next'
import api from '../api.js'

const PREVIEW_EXTS = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg', 'pdf', 'txt', 'md', 'json', 'xml', 'yaml', 'yml', 'csv', 'log']

export default {
  components: { 
    Home, ChevronRight, ChevronUp, ChevronDown, FolderPlus, Upload, 
    RotateCw, AlertCircle, X, Eye, Download, Pencil, Trash2, 
    File, FileImage, FileText, FileArchive, FileMusic, FileVideo, 
    FileQuestion, Folder, FolderOpen, RefreshCw
  },
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
    getFileIconComponent(item) {
      if (item.is_dir) return 'Folder'
      const ext = item.name.split('.').pop().toLowerCase()
      const map = {
        pdf: 'FileText',
        txt: 'FileText',
        md: 'FileText',
        json: 'FileText',
        jpg: 'FileImage',
        jpeg: 'FileImage',
        png: 'FileImage',
        gif: 'FileImage',
        webp: 'FileImage',
        zip: 'FileArchive',
        rar: 'FileArchive',
        '7z': 'FileArchive',
        mp3: 'FileMusic',
        wav: 'FileMusic',
        mp4: 'FileVideo',
        mkv: 'FileVideo',
      }
      return map[ext] || 'File'
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
.files-container { height: 100%; display: flex; flex-direction: column; gap: 16px; }

.toolbar { 
  display: flex; 
  align-items: center; 
  justify-content: space-between; 
  background: var(--bg-card); 
  padding: 12px 20px; 
  border-radius: var(--radius-lg); 
  box-shadow: var(--shadow-sm); 
  border: 1px solid var(--border-base);
}
.breadcrumb-bar { flex: 1; display: flex; align-items: center; min-width: 0; font-size: 14px; }
.btn-crumb { 
  border: none; 
  background: transparent; 
  padding: 6px 10px; 
  color: var(--brand); 
  cursor: pointer; 
  border-radius: var(--radius-sm); 
  transition: all 0.2s; 
  white-space: nowrap; 
  display: flex;
  align-items: center;
  gap: 6px;
  font-weight: 500;
}
.btn-crumb:hover { background: var(--bg-info); }
.btn-crumb.is-last { color: var(--text-primary); font-weight: 600; cursor: default; pointer-events: none; }
.sep { color: var(--text-quaternary); margin: 0 4px; opacity: 0.5; }

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
  color: var(--text-secondary);
}
.btn-tool:hover { border-color: var(--brand); color: var(--brand); background: var(--bg-info); }
.btn-tool.btn-primary { background: var(--brand); color: var(--text-inverse); border-color: var(--brand); }
.btn-tool.btn-primary:hover { opacity: 0.9; box-shadow: 0 4px 12px hsla(var(--brand-hue) var(--brand-sat) var(--brand-lit) / 0.2); }

.spinning { animation: spin 1s linear infinite; }
@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }

.error-alert { background: var(--bg-danger); border: 1px solid var(--danger-border); color: var(--danger-text); padding: 10px 16px; border-radius: var(--radius-md); display: flex; align-items: center; gap: 12px; }
.btn-close { margin-left: auto; border: none; background: transparent; cursor: pointer; font-size: 18px; color: var(--text-tertiary); }

.files-list-wrapper { 
  flex: 1; 
  background: var(--bg-card); 
  border-radius: var(--radius-lg); 
  box-shadow: var(--shadow-sm); 
  overflow-y: auto; 
  border: 1px solid var(--border-base);
}
.files-table { width: 100%; border-collapse: collapse; table-layout: fixed; }
.files-table th { background: var(--bg-table-header); padding: 16px 20px; text-align: left; font-size: 13px; font-weight: 600; color: var(--text-secondary); border-bottom: 1px solid var(--border-base); user-select: none; }
.files-table th.sortable { cursor: pointer; }
.files-table th.sortable:hover { color: var(--brand); }
.sort-indicator { margin-left: 4px; vertical-align: middle; color: var(--brand); }
.files-table td { padding: 14px 20px; border-bottom: 1px solid var(--border-base); font-size: 14px; color: var(--text-primary); }

.col-name { width: 45%; }
.col-size { width: 15%; }
.col-time { width: 20%; }
.col-actions { width: 20%; text-align: right !important; }

.file-row { transition: background .15s; }
.file-row:hover { background: var(--bg-table-header); }
.name-box { display: flex; align-items: center; gap: 12px; transition: color .2s; }
.name-box.is-clickable { cursor: pointer; }
.name-box.is-clickable:hover .file-name { color: var(--brand); }
.file-icon-comp { color: var(--text-tertiary); flex-shrink: 0; }
.dir-icon { color: var(--brand); opacity: 0.8; }
.file-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-weight: 500; }
.file-name.is-dir { color: var(--text-primary); }

.row-actions { display: flex; justify-content: flex-end; gap: 4px; opacity: 0.3; transition: opacity .2s; }
.file-row:hover .row-actions { opacity: 1; }
.btn-icon { width: 34px; height: 34px; display: inline-flex; align-items: center; justify-content: center; border: 1px solid transparent; border-radius: var(--radius-sm); background: transparent; cursor: pointer; text-decoration: none; color: var(--text-secondary); transition: all 0.2s; }
.btn-icon:hover { border-color: var(--border-base); background: white; color: var(--brand); box-shadow: var(--shadow-sm); }
.btn-icon.btn-danger:hover { color: var(--danger); background: var(--bg-danger); border-color: var(--danger-border); }

.empty-state, .loading-state { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 80px; color: var(--text-tertiary); }
.empty-icon { color: var(--border-strong); margin-bottom: 16px; opacity: 0.5; }

.inline-modal-overlay { position: fixed; inset: 0; z-index: 1000; background: rgba(0,0,0,0.3); display: flex; align-items: center; justify-content: center; backdrop-filter: blur(4px); }
.inline-dialog { background: var(--bg-card); width: 400px; padding: 28px; border-radius: var(--radius-lg); box-shadow: var(--shadow-xl); border: 1px solid var(--glass-border); }
.inline-dialog h3 { margin: 0 0 20px; font-size: 18px; }
.inline-dialog input { width: 100%; padding: 12px; border: 1px solid var(--border-input); border-radius: var(--radius-md); margin-bottom: 24px; box-sizing: border-box; font-size: 15px; }
.dialog-actions { display: flex; justify-content: flex-end; gap: 12px; }

.preview-dialog { background: var(--bg-card); width: 90vw; height: 85vh; max-width: 1100px; border-radius: var(--radius-lg); display: flex; flex-direction: column; overflow: hidden; box-shadow: var(--shadow-xl); border: 1px solid var(--glass-border); }
.preview-header { display: flex; justify-content: space-between; align-items: center; padding: 16px 24px; border-bottom: 1px solid var(--border-base); }
.preview-header h3 { margin: 0; font-size: 16px; font-weight: 600; }
.btn-close-preview { border: none; background: transparent; cursor: pointer; color: var(--text-tertiary); padding: 4px; border-radius: 50%; display: flex; transition: .2s; }
.btn-close-preview:hover { background: var(--bg-hover); color: var(--text-primary); }

.preview-body { flex: 1; overflow: hidden; background: #fafafa; }
.preview-iframe { width: 100%; height: 100%; border: none; background: white; }

.img-viewport { width: 100%; height: 100%; overflow: hidden; display: flex; align-items: center; justify-content: center; position: relative; }
.preview-img { max-width: 95%; max-height: 95%; cursor: grab; user-select: none; transition: transform 0.1s ease-out; filter: drop-shadow(0 10px 30px rgba(0,0,0,0.1)); }
.preview-img.dragging { cursor: grabbing; transition: none; }
.img-zoom-bar { position: absolute; bottom: 24px; left: 50%; transform: translateX(-50%); background: rgba(0,0,0,0.7); border-radius: 30px; display: flex; align-items: center; gap: 4px; padding: 6px 12px; backdrop-filter: blur(8px); }
.zoom-btn { border: none; background: transparent; color: #fff; width: 32px; height: 32px; border-radius: 50%; cursor: pointer; font-size: 18px; display: flex; align-items: center; justify-content: center; }
.zoom-btn:hover { background: rgba(255,255,255,0.2); }
.zoom-label { color: #fff; font-size: 13px; min-width: 50px; text-align: center; font-weight: 500; }

.dropzone-overlay { position: fixed; inset: 0; z-index: 2000; background: hsla(var(--brand-hue), var(--brand-sat), var(--brand-lit), 0.1); display: flex; align-items: center; justify-content: center; backdrop-filter: blur(8px); }
.dropzone-content { background: white; border: 2px dashed var(--brand); border-radius: 32px; padding: 60px 100px; text-align: center; box-shadow: var(--shadow-xl); }
.drop-icon { color: var(--brand); margin-bottom: 20px; }
.dropzone-content p { font-size: 20px; color: var(--text-primary); font-weight: 600; margin: 0; }
</style>
