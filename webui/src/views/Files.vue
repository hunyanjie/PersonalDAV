<template>
  <div class="files-container">
    <div class="toolbar glass">
      <div class="breadcrumb-wrapper">
        <div class="breadcrumb-bar">
          <button class="btn-crumb" @click="cd('')"><Home :size="18" /> <span class="hide-mobile">根目录</span></button>
          <template v-for="(seg, i) in breadcrumbs" :key="i">
            <ChevronRight :size="14" class="sep" />
            <button class="btn-crumb" :class="{ 'is-last': i === breadcrumbs.length - 1 }" @click="cd(seg.path)">
              {{ seg.name }}
            </button>
          </template>
        </div>
      </div>
      <div class="toolbar-actions">
        <button class="btn-tool" @click="showNewFolder = true" title="新建目录">
          <FolderPlus :size="18" /> <span class="hide-mobile">目录</span>
        </button>
        <label class="btn-tool btn-primary" title="上传文件">
          <Upload :size="18" /> <span class="hide-mobile">上传</span>
          <input type="file" multiple @change="doUpload" hidden />
        </label>
        <div v-if="uploadProgress !== null" class="upload-progress">
          <div class="progress-bar">
            <div class="progress-fill" :style="{ width: uploadProgress + '%' }"></div>
          </div>
          <span class="progress-text">{{ uploadProgress }}%</span>
        </div>
        <button class="btn-tool" @click="load" title="刷新">
          <RotateCw :size="18" :class="{ 'spinning': loading }" />
        </button>
      </div>
    </div>

    <div v-if="errorMsg" class="error-alert">
      <AlertCircle :size="18" /> {{ errorMsg }}
      <button class="btn-close" @click="errorMsg = ''">&times;</button>
    </div>

    <!-- Modals -->
    <transition name="modal">
      <div v-if="showNewFolder" class="inline-modal-overlay" @click.self="showNewFolder = false">
        <div class="inline-dialog glass no-transition">
          <h3>创建新目录</h3>
          <input v-model="newFolderName" placeholder="请输入目录名称" @keyup.enter="doMkdir" autofocus />
          <div class="dialog-actions">
            <button class="btn-sm" @click="showNewFolder = false">取消</button>
            <button class="btn-sm btn-primary" @click="doMkdir">创建</button>
          </div>
        </div>
      </div>
    </transition>

    <div v-if="dragOver" class="dropzone-overlay"
      @dragenter.prevent @dragover.prevent @dragleave.prevent="dragOver = false"
      @drop.prevent="onDrop">
      <div class="dropzone-content glass">
        <div class="drop-icon"><Upload :size="48" /></div>
        <p>释放以上传文件</p>
      </div>
    </div>

    <transition name="modal">
      <div v-if="renaming" class="inline-modal-overlay" @click.self="renaming = null">
        <div class="inline-dialog glass no-transition">
          <h3>重命名</h3>
          <input v-model="renameName" placeholder="请输入新名称" @keyup.enter="doRename" autofocus />
          <div class="dialog-actions">
            <button class="btn-sm" @click="renaming = null">取消</button>
            <button class="btn-sm btn-primary" @click="doRename">重命名</button>
          </div>
        </div>
      </div>
    </transition>

    <transition name="modal">
      <div v-if="showPreviewSelector" class="inline-modal-overlay" @click.self="showPreviewSelector = false">
        <div class="inline-dialog glass no-transition" style="max-width: 480px;">
          <h3>选择预览方式</h3>
          <p style="font-size: 14px; color: var(--text-secondary); margin-bottom: 20px;">请选择 "{{ previewSelectorItem?.name }}" 的预览方式：</p>
          <div class="selector-options">
            <button class="selector-btn" @click="selectPreviewMode('ms_online')">
              <div class="opt-icon" style="background: var(--bg-info); color: var(--brand);"><ExternalLink :size="20" /></div>
              <div class="opt-text">
                <div class="opt-title">微软 Office Online</div>
                <div class="opt-desc">使用微软云端服务预览。注意：文件需公网可访问（localhost 或内网 IP 无法使用）</div>
              </div>
            </button>
            <button class="selector-btn" @click="selectPreviewMode('local')">
              <div class="opt-icon" style="background: var(--bg-success); color: var(--success);"><Eye :size="20" /></div>
              <div class="opt-text">
                <div class="opt-title">本地转换预览</div>
                <div class="opt-desc">由服务器转换（需安装 LibreOffice/ONLYOFFICE）</div>
              </div>
            </button>
          </div>
          <div class="dialog-actions">
            <button class="btn-sm" @click="showPreviewSelector = false">取消</button>
          </div>
        </div>
      </div>
    </transition>

    <!-- Text / code editor -->
    <transition name="modal">
      <div v-if="textItem" class="preview-overlay" @click.self="closeText">
        <div class="preview-dialog glass no-transition editor-dialog">
          <div class="preview-header">
            <h3><Code2 :size="18" /> {{ textItem.name }}</h3>
            <div class="editor-header-actions">
              <button class="btn-icon-soft" :class="{ active: textWrap }" @click="textWrap = !textWrap" title="自动换行"><WrapText :size="17" /></button>
              <button v-if="!textEditing" class="btn-icon-soft" @click="textEditing = true" title="编辑"><Pencil :size="17" /></button>
              <button class="btn-icon-soft" @click="closeText" title="关闭"><X :size="18" /></button>
            </div>
          </div>
          <div class="editor-body" :class="{ 'wrap-lines': textWrap }">
            <div v-if="textLoading" class="preview-error">正在读取文件...</div>
            <div v-else-if="textError" class="preview-error">{{ textError }}</div>
            <textarea v-else-if="textEditing" v-model="textContent" class="code-textarea" spellcheck="false"
              @keydown.ctrl.s.prevent="saveText" @keydown.esc="closeText"></textarea>
            <pre v-else class="code-view" v-html="highlightedText"></pre>
          </div>
          <div class="preview-footer editor-footer">
            <span class="editor-meta">{{ textEncoding }} · {{ formatSize(textContent.length) }}</span>
            <button v-if="textEditing" class="btn-sm btn-primary" @click="saveText" :disabled="textSaving">
              <Save :size="14" /> {{ textSaving ? '保存中...' : '保存' }}
            </button>
            <button v-if="textEditing" class="btn-sm" @click="textEditing = false">取消编辑</button>
            <button v-else class="btn-sm" @click="textEditing = true"><Pencil :size="14" /> 编辑</button>
            <button class="btn-sm" @click="closeText">关闭</button>
          </div>
        </div>
      </div>
    </transition>

    <!-- Archive browser -->
    <transition name="modal">
      <div v-if="archiveItem" class="preview-overlay" @click.self="closeArchive">
        <div class="preview-dialog glass no-transition archive-dialog">
          <div class="preview-header">
            <h3><Archive :size="18" /> {{ archiveItem.name }}</h3>
            <button class="btn-icon-soft" @click="closeArchive" title="关闭"><X :size="18" /></button>
          </div>
          <div class="archive-toolbar">
            <input v-model="archiveFilter" class="archive-filter" placeholder="筛选压缩包内文件..." />
            <span class="archive-count">{{ archiveEntries.length }} 项</span>
            <span v-if="archiveNeedsPassword" class="archive-lock"><Lock :size="13" /> 已加密</span>
          </div>
          <div class="archive-body">
            <div class="archive-list">
              <div v-if="archiveLoading" class="preview-error">正在读取压缩包...</div>
              <div v-else-if="archiveError" class="preview-error">{{ archiveError }}</div>
              <div v-else-if="!filteredArchiveEntries.length" class="preview-error">压缩包为空</div>
              <div v-for="entry in filteredArchiveEntries" :key="entry.name"
                class="archive-entry" :class="{ selected: archiveEntry?.name === entry.name, dir: entry.is_dir }"
                @click="previewArchiveEntry(entry)">
                <component :is="entry.is_dir ? 'Folder' : 'File'" :size="15" />
                <span class="archive-name" :title="entry.name">{{ entry.name }}</span>
                <Lock v-if="entry.encrypted" :size="12" class="entry-lock" />
                <span v-if="!entry.is_dir" class="archive-size">{{ formatArchiveSize(entry.size) }}</span>
              </div>
            </div>
            <div class="archive-preview">
              <div v-if="archivePreviewLoading" class="preview-error">正在读取文件内容...</div>
              <div v-else-if="!archiveEntry" class="archive-placeholder">选择一个文件查看内容</div>
              <div v-else-if="archiveEntry.is_dir" class="archive-placeholder">这是一个目录</div>
              <div v-else-if="archivePreview?.error" class="preview-error">{{ archivePreview.error }}</div>
              <img v-else-if="archivePreview?.data_url" :src="archivePreview.data_url" class="archive-image" />
              <pre v-else-if="archivePreview?.is_text" class="archive-text">{{ archivePreview.content }}</pre>
              <div v-else-if="archivePreview" class="archive-placeholder">此文件类型不支持直接预览，可提取后打开。</div>
              <div v-else class="archive-placeholder">选择一个文件查看内容</div>
            </div>
          </div>
          <div class="preview-footer">
            <button v-if="archiveEntry && !archiveEntry.is_dir" class="btn-sm btn-primary" @click="extractArchiveEntry(archiveEntry)">
              提取到当前目录
            </button>
            <button class="btn-sm" @click="closeArchive">关闭</button>
          </div>
          <div v-if="archivePrompt" class="archive-password-overlay">
            <div class="archive-password-box glass">
              <h4><Lock :size="16" /> 需要解压密码</h4>
              <p>该压缩包已加密，请输入密码。密码会保留到当前标签页关闭。</p>
              <input v-model="archivePrompt.value" class="archive-password-input" type="password"
                placeholder="压缩包密码" @keyup.enter="confirmArchivePassword" />
              <div class="dialog-actions">
                <button class="btn-sm" @click="archivePrompt = null">取消</button>
                <button class="btn-sm btn-primary" @click="confirmArchivePassword">确定</button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </transition>

    <!-- Contact / calendar card -->
    <transition name="modal">
      <div v-if="cardItem" class="preview-overlay" @click.self="closeCard">
        <div class="preview-dialog glass no-transition card-dialog">
          <div class="preview-header">
            <h3>
              <component :is="cardKind === 'contact' ? 'Contact' : 'CalendarClock'" :size="18" />
              {{ cardItem.name }}
            </h3>
            <button class="btn-icon-soft" @click="closeCard" title="关闭"><X :size="18" /></button>
          </div>
          <div class="preview-body card-body">
            <div v-if="cardLoading" class="preview-error">正在解析卡片...</div>
            <div v-else-if="cardError" class="preview-error">{{ cardError }}</div>
            <div v-else-if="cardData" class="card-form">
              <template v-if="cardKind === 'contact'">
                <label>姓名<input v-model="cardData.full_name" /></label>
                <label>邮箱<input v-model="cardData.email" /></label>
                <label>电话<input v-model="cardData.phone" /></label>
                <label>分组<input v-model="cardData.groups" /></label>
                <label>公司<input v-model="cardData.org" /></label>
                <label>地址<input v-model="cardData.address" /></label>
                <label class="full">备注<textarea v-model="cardData.note" rows="4"></textarea></label>
              </template>
              <template v-else>
                <label class="full">标题<input v-model="cardData.summary" /></label>
                <label>开始<input v-model="cardData.dtstart" placeholder="2026-11-24T10:00" /></label>
                <label>结束<input v-model="cardData.dtend" placeholder="2026-11-24T11:00" /></label>
                <label>地点<input v-model="cardData.location" /></label>
                <label>分类<input v-model="cardData.categories" /></label>
                <label class="full">备注<textarea v-model="cardData.description" rows="4"></textarea></label>
                <label class="full">重复规则<input v-model="cardData.rrule" placeholder="例如 FREQ=WEEKLY;BYDAY=MO" /></label>
              </template>
            </div>
          </div>
          <div class="preview-footer">
            <button v-if="cardData" class="btn-sm btn-primary" @click="saveCard" :disabled="cardSaving">
              <Save :size="14" /> {{ cardSaving ? '保存中...' : '保存' }}
            </button>
            <button v-if="cardData" class="btn-sm" @click="editCardRaw">原始文本编辑</button>
            <button class="btn-sm" @click="closeCard">关闭</button>
          </div>
        </div>
      </div>
    </transition>

    <!-- Preview Modal (FIXED CSS) -->
    <transition name="modal">
      <div v-if="previewItem" class="preview-overlay" @click.self="previewItem = null">
        <div class="preview-dialog glass no-transition">
          <div class="preview-header">
            <h3>{{ previewItem.name }}</h3>
            <button class="btn-close-preview" @click="previewItem = null"><X :size="20" /></button>
          </div>
          <div class="preview-body">
            <template v-if="previewSrc">
              <div v-if="_isImage" class="img-viewport" ref="imgViewport"
                @wheel.prevent="onImgWheel"
                @mousedown="onImgDown" @mousemove="onImgMove" @mouseup="onImgUp" @mouseleave="onImgUp"
                @touchstart="onImgTouchStart" @touchmove="onImgTouchMove" @touchend="onImgTouchEnd">
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
              <button class="btn-sm btn-primary" @click="api().downloadFile(previewItem.path)">下载</button>
            <button class="btn-sm" @click="previewItem = null">关闭</button>
          </div>
        </div>
      </div>
    </transition>

    <!-- Tab bar: 文件 | 回收站 -->
    <div class="tab-bar">
      <button class="tab-btn" :class="{ active: tab === 'files' }" @click="switchTab('files')"><File :size="16" /> 文件</button>
      <button class="tab-btn" :class="{ active: tab === 'trash' }" @click="switchTab('trash')"><Trash2 :size="16" /> 回收站</button>
    </div>

    <div v-if="tab === 'files'" class="files-list-wrapper glass">
      <div v-if="sortedItems.length" class="table-container">
        <table class="files-table">
          <thead>
            <tr>
              <th class="col-name sortable" @click="toggleSort('name')">
                名称
                <span v-if="sortField === 'name'" class="sort-indicator">
                  <ChevronUp v-if="sortDir === 'asc'" :size="12" />
                  <ChevronDown v-else :size="12" />
                </span>
              </th>
              <th class="col-size sortable hide-mobile" @click="toggleSort('size')">
                大小
                <span v-if="sortField === 'size'" class="sort-indicator">
                  <ChevronUp v-if="sortDir === 'asc'" :size="12" />
                  <ChevronDown v-else :size="12" />
                </span>
              </th>
              <th class="col-time sortable hide-tablet" @click="toggleSort('modified_at')">
                修改时间
                <span v-if="sortField === 'modified_at'" class="sort-indicator">
                  <ChevronUp v-if="sortDir === 'asc'" :size="12" />
                  <ChevronDown v-else :size="12" />
                </span>
              </th>
              <th class="col-actions">操作</th>
            </tr>
          </thead>
          <transition-group tag="tbody" name="list">
            <tr v-for="item in sortedItems" :key="item.path" class="file-row"
              :class="{ 'swipe-open': _swipePath === item.path, 'menu-active': _menuPath === item.path }"
              @touchstart="swipeStart(item.path, $event)"
              @touchmove="swipeMove($event)"
              @touchend="swipeEnd(item.path)">
              <td class="col-name">
                <div class="file-main-info" @click="item.is_dir ? cd(item.path) : null" @dblclick="!item.is_dir && canPreview(item.name) && doPreview(item)">
                  <component :is="getFileIconComponent(item)" class="file-icon-comp" :class="{ 'dir-icon': item.is_dir }" :size="20" />
                  <div class="file-text-wrapper">
                    <span class="file-name" :class="{ 'is-dir': item.is_dir }">{{ item.name }}</span>
                    <div class="mobile-meta">
                      <span class="meta-time">{{ formatDate(item.modified_at) }}</span>
                      <span class="meta-sep">·</span>
                      <span class="meta-size">{{ item.is_dir ? '目录' : formatSize(item.size) }}</span>
                    </div>
                  </div>
                </div>
              </td>
              <td class="col-size hide-mobile">{{ item.is_dir ? '-' : formatSize(item.size) }}</td>
              <td class="col-time hide-tablet">{{ formatDate(item.modified_at) }}</td>
              <td class="col-actions">
                <button class="btn-icon btn-more-trigger" @click.stop="toggleMenu(item.path)" title="更多">
                  <MoreHorizontal :size="20" />
                </button>
                <div class="row-actions-main" :style="swipeStyle(item.path)">
                  <button v-if="!item.is_dir && canPreview(item.name)" class="btn-icon" @touchstart.stop @click.stop="doPreview(item)" title="预览"><Eye :size="16" /></button>
                  <button v-if="!item.is_dir" class="btn-icon" @touchstart.stop @click.stop="api().downloadFile(item.path)" title="下载"><Download :size="16" /></button>
                  <button class="btn-icon" @touchstart.stop @click.stop="startRename(item)" title="重命名"><Pencil :size="16" /></button>
                  <button class="btn-icon btn-danger" @touchstart.stop @click.stop="doDelete(item)" title="删除"><Trash2 :size="16" /></button>
                </div>
                <transition name="pop">
                  <div v-if="_menuPath === item.path" class="ctx-menu-popover glass" @click.stop>
                    <div v-if="!item.is_dir && canPreview(item.name)" class="ctx-item" @click="doPreview(item); _menuPath = null"><Eye :size="16" /> 预览文件</div>
                    <div v-if="!item.is_dir" class="ctx-item" @click="api().downloadFile(item.path); _menuPath = null"><Download :size="16" /> 下载文件</div>
                    <div class="ctx-item" @click="startRename(item); _menuPath = null"><Pencil :size="16" /> 重命名</div>
                    <div class="ctx-divider" />
                    <div class="ctx-item danger" @click="doDelete(item); _menuPath = null"><Trash2 :size="16" /> 删除项</div>
                  </div>
                </transition>
              </td>
            </tr>
          </transition-group>
        </table>
      </div>
      <div v-else-if="!loading" class="empty-state">
        <div class="empty-icon"><FolderOpen :size="48" /></div>
        <p>此目录空空如也</p>
      </div>
      <div v-if="loading && !items.length" class="loading-state">正在加载文件列表...</div>
    </div>

    <!-- Trash view -->
    <div v-if="tab === 'trash'" class="files-list-wrapper glass">
      <div class="trash-toolbar">
        <span class="trash-count">共 {{ trashItems.length }} 项</span>
        <button class="btn-sm btn-danger" @click="purgeTrash" :disabled="!trashItems.length">清空回收站</button>
      </div>
      <div v-if="trashItems.length" class="table-container">
        <table class="files-table">
          <thead>
            <tr>
              <th class="col-name">原路径</th>
              <th class="col-size hide-mobile">大小</th>
              <th class="col-time hide-tablet">删除时间</th>
              <th class="col-actions">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in trashItems" :key="item.uuid" class="file-row">
              <td class="col-name">
                <div class="file-main-info">
                  <component :is="item.is_dir ? 'Folder' : 'File'" class="file-icon-comp" :size="20" />
                  <span class="file-name">{{ item.original_path }}</span>
                </div>
              </td>
              <td class="col-size hide-mobile">{{ item.is_dir ? '目录' : formatSize(item.size) }}</td>
              <td class="col-time hide-tablet">{{ formatDate(item.deleted_at) }}</td>
              <td class="col-actions">
              <div style="display: flex; justify-content: flex-end; gap: 6px;">
              <button class="btn-icon" @click="restoreFromTrash(item)" title="还原"><RefreshCw :size="16" /></button>
              <button class="btn-icon btn-danger" @click="deleteFromTrash(item)" title="永久删除"><Trash2 :size="16" /></button>
              </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else class="empty-state">
        <div class="empty-icon"><Trash2 :size="48" /></div>
        <p>回收站空空如也</p>
      </div>
    </div>
  </div>
</template>

<script>
import { 
  Home, ChevronRight, ChevronUp, ChevronDown, FolderPlus, Upload, 
  RotateCw, AlertCircle, X, Eye, Download, Pencil, Trash2, 
  File, FileImage, FileText, FileArchive, FileMusic, FileVideo, 
  FileQuestion, Folder, FolderOpen, RefreshCw, MoreHorizontal,
  ExternalLink, Lock, Save, WrapText, Code2, Archive, Contact, CalendarClock
} from 'lucide-vue-next'
import api from '../api.js'
import 'highlight.js/styles/github.css'
import hljs from 'highlight.js/lib/core'
import javascript from 'highlight.js/lib/languages/javascript'
import typescript from 'highlight.js/lib/languages/typescript'
import python from 'highlight.js/lib/languages/python'
import java from 'highlight.js/lib/languages/java'
import markdown from 'highlight.js/lib/languages/markdown'
import json from 'highlight.js/lib/languages/json'
import xml from 'highlight.js/lib/languages/xml'
import css from 'highlight.js/lib/languages/css'
import sql from 'highlight.js/lib/languages/sql'
import bash from 'highlight.js/lib/languages/bash'
import yaml from 'highlight.js/lib/languages/yaml'
import ini from 'highlight.js/lib/languages/ini'
import cpp from 'highlight.js/lib/languages/cpp'
import csharp from 'highlight.js/lib/languages/csharp'
import go from 'highlight.js/lib/languages/go'
import rust from 'highlight.js/lib/languages/rust'
import php from 'highlight.js/lib/languages/php'

for (const [name, lang] of Object.entries({
  javascript, typescript, python, java, markdown, json, xml, css, sql,
  bash, yaml, ini, cpp, csharp, go, rust, php,
})) hljs.registerLanguage(name, lang)

const TEXT_EXTS = ['txt', 'md', 'markdown', 'json', 'xml', 'yaml', 'yml', 'csv', 'log', 'ini', 'conf', 'cfg', 'py', 'java', 'js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx', 'vue', 'html', 'htm', 'css', 'scss', 'less', 'sql', 'sh', 'ps1', 'bat', 'cmd', 'c', 'h', 'cpp', 'hpp', 'cs', 'go', 'rs', 'php', 'rb', 'toml', 'properties', 'gitignore', 'env', 'text']
const ARCHIVE_EXTS = ['zip', 'tar', 'gz', 'tgz', 'bz2', 'tbz2', 'xz', 'txz', '7z', 'rar']
const CARD_EXTS = ['vcf', 'vcs', 'ics', 'ical']
const PREVIEW_EXTS = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', ...TEXT_EXTS, ...ARCHIVE_EXTS, ...CARD_EXTS]
const OFFICE_EXTS = ['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx']
const LANG_MAP = {
  js: 'javascript', mjs: 'javascript', cjs: 'javascript', jsx: 'javascript',
  ts: 'typescript', tsx: 'typescript', vue: 'xml', html: 'xml', htm: 'xml',
  py: 'python', java: 'java', md: 'markdown', markdown: 'markdown',
  json: 'json', xml: 'xml', css: 'css', scss: 'css', less: 'css',
  sql: 'sql', sh: 'bash', ps1: 'bash', bat: 'bash', cmd: 'bash',
  yaml: 'yaml', yml: 'yaml', ini: 'ini', conf: 'ini', cfg: 'ini', toml: 'ini',
  c: 'cpp', h: 'cpp', cpp: 'cpp', hpp: 'cpp', cs: 'csharp', go: 'go', rs: 'rust', php: 'php',
}

export default {
  components: { 
    Home, ChevronRight, ChevronUp, ChevronDown, FolderPlus, Upload, 
    RotateCw, AlertCircle, X, Eye, Download, Pencil, Trash2, 
    File, FileImage, FileText, FileArchive, FileMusic, FileVideo, 
    FileQuestion, Folder, FolderOpen, RefreshCw, MoreHorizontal,
    ExternalLink, Lock, Save, WrapText, Code2, Archive, Contact, CalendarClock
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
    uploadProgress: null,
    _swipePath: null, _swipeOffset: 0, _swipeStartX: 0, _swipeStartY: 0,
    _menuPath: null, _isDragging: false,
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
    tab: 'files',
    trashItems: [],
    _officeMode: 'off',
    showPreviewSelector: false,
    previewSelectorItem: null,
    // Text editor
    textItem: null, textContent: '', textEncoding: 'utf-8', textMtime: null,
    textLoading: false, textSaving: false, textWrap: true, textEditing: false,
    textError: '',
    // Archive browser
    archiveItem: null, archiveEntries: [], archiveLoading: false, archiveError: '',
    archivePassword: '', archiveNeedsPassword: false, archiveNamesEncrypted: false,
    archiveEntry: null, archivePreview: null, archivePreviewLoading: false,
    archiveFilter: '', archivePrompt: null,
    // Card viewer/editor
    cardItem: null, cardKind: '', cardData: null, cardLoading: false,
    cardSaving: false, cardError: '',
  }),
  mounted() { 
    this.updateBreadcrumbs()
    this.load()
    this._loadOfficeMode()
    document.addEventListener('dragenter', this.onDragEnter)
    document.addEventListener('click', this._closeMenu)
  },
  beforeUnmount() {
    document.removeEventListener('dragenter', this.onDragEnter)
    document.removeEventListener('click', this._closeMenu)
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
    textLanguage() {
      const ext = this.textItem?.name?.split('.').pop()?.toLowerCase() || ''
      return LANG_MAP[ext] || null
    },
    highlightedText() {
      const code = this.textContent || ''
      try {
        if (this.textLanguage) return hljs.highlight(code, { language: this.textLanguage }).value
      } catch (e) { /* 回退到纯文本 */ }
      return code.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    },
    filteredArchiveEntries() {
      const q = this.archiveFilter.trim().toLowerCase()
      if (!q) return this.archiveEntries
      return this.archiveEntries.filter((e) => e.name.toLowerCase().includes(q))
    },
  },
  methods: {
    api() { return api },
    switchTab(t) {
      this.tab = t
      if (t === 'trash') this.loadTrash()
    },
    async loadTrash() {
      try {
        const res = await api.listTrash()
        this.trashItems = res.items || []
      } catch(e) { window.showToast('加载回收站失败', 'error'); this.trashItems = [] }
    },
    async restoreFromTrash(item) {
      this.doTrashOp(item.uuid, 'restore', item.absolute_path || item.original_path.replace(/^\/+/, ''))
    },
    deleteFromTrash(item) {
      this.doTrashOp(item.uuid, 'delete', item.absolute_path || item.original_path.replace(/^\/+/, ''))
    },
    async doTrashOp(uuid, op, targetPath = null, conflictStrategy = 'error') {
      try {
        if (op === 'restore') {
          await api.restoreTrash(uuid, targetPath, conflictStrategy)
          window.showToast('还原成功', 'success')
        } else {
          await api.deleteTrashItem(uuid)
          window.showToast('删除成功', 'success')
        }
        this.loadTrash()
      } catch(e) { 
        if (e.status === 409) {
          const action = await window.showConfirm({ 
            message: `文件冲突：${e.message || '文件已存在'}，请选择：覆盖(确定) / 重命名(取消)`, 
            type: 'warning',
            confirmText: '覆盖',
            cancelText: '重命名'
          })
          if (action === true) {
            this.doTrashOp(uuid, 'restore', targetPath, 'overwrite')
            return
          } else if (action === false) {
            const newPath = await window.showPrompt({ 
              title: "重命名", 
              message: "请输入新的保存路径", 
              initialValue: targetPath 
            })
            if (newPath) this.doTrashOp(uuid, 'restore', newPath, 'error')
            return
          }
        }
        window.showToast(op === 'restore' ? '还原失败' : '删除失败', 'error') 
      }
    },
    async purgeTrash() {
      if (!window.showConfirm) { this.doPurge(); return }
      const ok = await window.showConfirm({ message: '永久清空回收站所有条目？无法恢复！', type: 'danger' })
      if (!ok) return
      try {
        await api.purgeTrash(0)
        this.loadTrash()
        window.showToast('回收站已清空', 'success')
      } catch(e) { window.showToast('清空失败', 'error') }
    },
    toggleSort(field) {
      if (this.sortField === field) this.sortDir = this.sortDir === 'asc' ? 'desc' : 'asc'
      else { this.sortField = field; this.sortDir = 'asc' }
    },
    canPreview(name) {
      const ext = name.includes('.') ? name.split('.').pop().toLowerCase() : ''
      return PREVIEW_EXTS.includes(ext) || (!ext && name !== '.')
    },
    async doPreview(item) {
      const ext = item.name.includes('.') ? item.name.split('.').pop().toLowerCase() : ''
      if (ARCHIVE_EXTS.includes(ext)) return this.openArchive(item)
      if (CARD_EXTS.includes(ext)) return this.openCard(item)
      if (TEXT_EXTS.includes(ext) || !ext) return this.openText(item)

      this._previewSrc = null
      this._previewError = ''
      this._isImage = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg'].includes(ext)

      // Office files
      if (OFFICE_EXTS.includes(ext)) {
        const mode = this._officeMode || 'off'
        if (mode === 'ms_online') {
          const absUrl = window.location.origin + '/api' + api.previewUrl(item.path).split('/api').pop()
          window.open(`https://view.officeapps.live.com/op/view.aspx?src=${encodeURIComponent(absUrl)}`, '_blank')
          this.previewItem = null
          return
        } else if (mode === 'libreoffice' || mode === 'onlyoffice') {
          // Use backend conversion preview
          try {
            this._previewSrc = await api.previewFile(item.path)
          } catch(e) {
            this._previewError = '预览失败：请检查是否已安装 LibreOffice'
          }
        } else if (mode === 'ask') {
          this.previewSelectorItem = item
          this.showPreviewSelector = true
          return
        } else {
          this._previewError = '不支持预览该文件类型（可在设置中开启 Office 预览）'
        }
        this.previewItem = item
        return
      }

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
    async selectPreviewMode(mode) {
      const item = this.previewSelectorItem
      this.showPreviewSelector = false
      this.previewSelectorItem = null
      
      if (mode === 'ms_online') {
        const absUrl = window.location.origin + '/api' + api.previewUrl(item.path).split('/api').pop()
        window.open(`https://view.officeapps.live.com/op/view.aspx?src=${encodeURIComponent(absUrl)}`, '_blank')
      } else {
        // local
        this._previewSrc = null
        this._previewError = ''
        this.previewItem = item
        this._zoom = 1
        this._panX = 0
        this._panY = 0
        this._isPanning = false
        try {
          this._previewSrc = await api.previewFile(item.path)
        } catch(e) {
          this._previewError = '预览失败：请检查服务器是否已安装 LibreOffice/ONLYOFFICE'
        }
      }
    },
    async _loadOfficeMode() {
      try { const r = await api.getSetting('office_preview_mode'); this._officeMode = r.value || 'off'
      } catch(e) { this._officeMode = 'off' }
    },

    // ── Text editor ──
    async openText(item) {
      this.textItem = item
      this.textContent = ''
      this.textError = ''
      this.textEditing = false
      this.textWrap = true
      this.textLoading = true
      try {
        const r = await api.readText(item.path)
        this.textContent = r.content || ''
        this.textEncoding = r.encoding || 'utf-8'
        this.textMtime = r.mtime
      } catch (e) {
        this.textError = e.message || String(e)
      } finally {
        this.textLoading = false
      }
    },
    async saveText() {
      if (!this.textItem) return
      this.textSaving = true
      try {
        const r = await api.saveText(this.textItem.path, this.textContent, this.textEncoding, this.textMtime)
        if (r.mtime) this.textMtime = r.mtime
        else {
          try { const fresh = await api.readText(this.textItem.path); this.textMtime = fresh.mtime } catch (e) {}
        }
        this.textEditing = false
        window.showToast('已保存', 'success')
        this.load()
      } catch (e) {
        window.showToast('保存失败：' + (e.message || e), 'error')
      } finally {
        this.textSaving = false
      }
    },
    closeText() { this.textItem = null; this.textContent = ''; this.textError = '' },

    // ── Archive browser ──
    _archivePasswordCache() {
      try { return JSON.parse(sessionStorage.getItem('pdav-archive-passwords') || '{}') }
      catch (e) { return {} }
    },
    archivePasswordFor(path) {
      return this._archivePasswordCache()[path] || ''
    },
    rememberArchivePassword(path, password) {
      if (!password) return
      const cache = this._archivePasswordCache()
      cache[path] = password
      try { sessionStorage.setItem('pdav-archive-passwords', JSON.stringify(cache)) } catch (e) {}
    },
    async openArchive(item) {
      this.archiveItem = item
      this.archiveEntries = []
      this.archiveEntry = null
      this.archivePreview = null
      this.archiveError = ''
      this.archiveFilter = ''
      this.archivePassword = this.archivePasswordFor(item.path)
      await this.loadArchive()
    },
    async loadArchive(password = null) {
      if (!this.archiveItem) return
      this.archiveLoading = true
      this.archiveError = ''
      const pwd = password === null ? this.archivePassword : password
      try {
        const r = await api.archiveList(this.archiveItem.path, pwd)
        this.archiveEntries = r.entries || []
        this.archiveNamesEncrypted = !!r.names_encrypted
        this.archiveNeedsPassword = !!r.password_required
        if (pwd) this.rememberArchivePassword(this.archiveItem.path, pwd)
        this.archivePassword = pwd
        if (r.names_encrypted && !this.archiveEntries.length) {
          this.askArchivePassword('list', null)
        }
      } catch (e) {
        this.archiveError = e.message || String(e)
        if (e.status === 401 || e.status === 403 || e.status === 423) this.askArchivePassword('list', null)
      } finally {
        this.archiveLoading = false
      }
    },
    askArchivePassword(action, entry) {
      this.archivePrompt = { action, entry, value: '' }
      this.$nextTick(() => {
        const el = this.$el?.querySelector('.archive-password-input')
        if (el) el.focus()
      })
    },
    confirmArchivePassword() {
      const prompt = this.archivePrompt
      if (!prompt) return
      const pwd = (prompt.value || '').trim()
      this.archivePrompt = null
      if (!pwd) return
      this.rememberArchivePassword(this.archiveItem.path, pwd)
      this.archivePassword = pwd
      if (prompt.action === 'list') this.loadArchive(pwd)
      else if (prompt.action === 'preview') this.previewArchiveEntry(prompt.entry, pwd)
      else if (prompt.action === 'extract') this.extractArchiveEntry(prompt.entry, pwd)
    },
    async previewArchiveEntry(entry, password = null) {
      this.archiveEntry = entry
      this.archivePreview = null
      if (entry.is_dir) return
      this.archivePreviewLoading = true
      const pwd = password === null ? this.archivePassword : password
      try {
        this.archivePreview = await api.archivePreview(this.archiveItem.path, entry.name, pwd)
        if (pwd) this.rememberArchivePassword(this.archiveItem.path, pwd)
      } catch (e) {
        if (e.status === 401 || e.status === 403 || e.status === 423) this.askArchivePassword('preview', entry)
        else this.archivePreview = { error: e.message || String(e) }
      } finally {
        this.archivePreviewLoading = false
      }
    },
    async extractArchiveEntry(entry, password = null) {
      if (!entry || entry.is_dir) return
      const target = this.archiveItem.path.includes('/')
        ? this.archiveItem.path.slice(0, this.archiveItem.path.lastIndexOf('/')) || '/'
        : '/'
      const pwd = password === null ? this.archivePassword : password
      try {
        const r = await api.archiveExtract(this.archiveItem.path, entry.name, target, pwd, false)
        if (pwd) this.rememberArchivePassword(this.archiveItem.path, pwd)
        window.showToast(`已提取：${r.name}`, 'success')
        this.load()
      } catch (e) {
        if (e.status === 401 || e.status === 403 || e.status === 423) this.askArchivePassword('extract', entry)
        else window.showToast('提取失败：' + (e.message || e), 'error')
      }
    },
    closeArchive() {
      this.archiveItem = null; this.archiveEntries = []; this.archiveEntry = null
      this.archivePreview = null; this.archivePrompt = null; this.archiveError = ''
    },
    archivePreviewText() {
      return this.archivePreview?.is_text ? this.archivePreview.content : ''
    },
    formatArchiveSize(size) { return this.formatSize(size) },

    // ── Contact / calendar card ──
    async openCard(item) {
      this.cardItem = item
      this.cardData = null
      this.cardKind = ''
      this.cardError = ''
      this.cardLoading = true
      try {
        const r = await api.readCard(item.path)
        this.cardKind = r.kind
        this.cardData = { ...(r.data || {}) }
      } catch (e) {
        this.cardError = e.message || String(e)
      } finally {
        this.cardLoading = false
      }
    },
    async saveCard() {
      if (!this.cardItem || !this.cardData) return
      this.cardSaving = true
      try {
        const r = await api.saveCard(this.cardItem.path, this.cardKind, this.cardData, this.cardData.uid || '')
        window.showToast('卡片已保存', 'success')
        this.cardData = { ...this.cardData }
        this.load()
        if (r.raw) this.closeCard()
      } catch (e) {
        window.showToast('保存失败：' + (e.message || e), 'error')
      } finally {
        this.cardSaving = false
      }
    },
    closeCard() { this.cardItem = null; this.cardData = null; this.cardKind = ''; this.cardError = '' },
    async editCardRaw() {
      const item = this.cardItem
      this.closeCard()
      if (item) await this.openText(item)
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
    onImgTouchStart(e) {
      if (this._zoom <= 1) return
      this._isPanning = true
      const t = e.touches[0]
      this._panStartX = t.clientX
      this._panStartY = t.clientY
      this._panStartPx = this._panX
      this._panStartPy = this._panY
    },
    onImgTouchMove(e) {
      if (!this._isPanning) return
      const t = e.touches[0]
      this._panX = this._panStartPx + (t.clientX - this._panStartX)
      this._panY = this._panStartPy + (t.clientY - this._panStartY)
    },
    onImgTouchEnd() { this._isPanning = false },
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
      this.$nextTick(() => this.scrollBreadcrumbEnd())
      this.load()
    },
    scrollBreadcrumbEnd() {
      const el = this.$el?.querySelector('.breadcrumb-wrapper')
      if (el) el.scrollLeft = el.scrollWidth
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
      this.uploadProgress = 0
      for (const file of files) {
        let uploadFile = file
        let newFilename = null
        let overwrite = false

        if (this.items.some(i => i.name === file.name)) {
          const action = await window.showConfirm({ 
            message: `"${file.name}" 已存在`, 
            type: 'warning',
            confirmText: '覆盖',
            cancelText: '取消',
            extraText: '重命名',
            showCancel: true
          })
          
          if (action === 'confirm') { // 覆盖
            overwrite = true
          } else if (action === 'extra') { // 重命名
             let name = file.name
             let ext = ''
             const lastDot = name.lastIndexOf('.')
             if (lastDot > 0) {
                 ext = name.substring(lastDot)
                 name = name.substring(0, lastDot)
             }
             let counter = 1
             let newName = `${name}(${counter})${ext}`
             while (this.items.some(i => i.name === newName)) {
                 counter++
                 newName = `${name}(${counter})${ext}`
             }
             newFilename = newName
          } else { // 取消或关闭
             window.showToast(`已取消上传: ${file.name}`, 'info')
             continue 
          }
        }

        try {
          await api.uploadFileWithProgress(uploadFile, this.currentPath, pct => { this.uploadProgress = pct }, overwrite, newFilename)
          window.showToast(`上传成功: ${newFilename || file.name}`, 'success')
        } catch(e) {
          window.showToast(`上传失败(${file.name}): ${e.message || e}`, 'error')
        }
      }
      setTimeout(() => {
        this.uploadProgress = null
      }, 1000)
      e.target.value = '' // 重置输入框
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
      } catch(e) { window.showToast('创建失败：' + (e.message || e), 'error') }
    },
    startRename(item) {
      this.renaming = item; this.renameName = item.name
    },
    swipeStart(path, e) {
      if (window.innerWidth > 768) return
      if (this._swipePath === path && this._swipeOffset === 160) return
      if (e.target.closest('.col-actions, .btn-more-trigger, .ctx-menu-popover')) return
      this._swipePath = path
      this._swipeStartX = e.touches[0].clientX
      this._swipeStartY = e.touches[0].clientY
      this._swipeOffset = 0
      this._isDragging = false
    },
    swipeMove(e) {
      if (!this._swipePath) return
      const dx = this._swipeStartX - e.touches[0].clientX
      const dy = Math.abs(this._swipeStartY - e.touches[0].clientY)
      if (dy > 40) { this.closeSwipe(); return }
      if (Math.abs(dx) > 30) {
        this._isDragging = true
        e.stopPropagation()
        this._swipeOffset = Math.max(0, Math.min(160, dx))
      }
    },
    swipeEnd(path) {
      const wasDragging = this._isDragging
      this._isDragging = false
      if (this._swipePath !== path) return
      if (wasDragging && this._swipeOffset > 80) {
        this._swipeOffset = 160
      } else if (wasDragging) {
        this.closeSwipe()
      }
    },
    closeSwipe() { this._swipePath = null; this._swipeOffset = 0; this._isDragging = false },
    toggleMenu(path) { this._menuPath = this._menuPath === path ? null : path },
    _closeMenu() { this._menuPath = null },
    swipeStyle(path) {
      if (window.innerWidth > 768) return {}
      if (this._swipePath !== path) return { transform: 'translateX(100%)' }
      const offset = 160 - this._swipeOffset
      const style = { transform: `translateX(${offset}px)` }
      if (this._isDragging) style.transition = 'none'
      else style.transition = 'transform 0.4s cubic-bezier(0.2, 0.8, 0.2, 1)'
      return style
    },
    async doRename() {
      const newName = this.renameName.trim()
      if (!newName || !this.renaming) return
      try {
        await api.renameFile(this.renaming.path, newName)
        this.renaming = null; this.renameName = ''
        this.load()
      } catch(e) { window.showToast('重命名失败：' + (e.message || e), 'error') }
    },
    async doDelete(item) {
      if (!await window.showConfirm({ message: `确认删除 ${item.name}？此操作无法撤销。`, type: 'danger' })) return
      try { 
        await api.deleteFile(item.path)
        this.load() 
      } catch(e) { window.showToast('删除失败：' + (e.message || e), 'error') }
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
        vcf: 'Contact',
        vcs: 'Contact',
        ics: 'CalendarClock',
        ical: 'CalendarClock',
        mp3: 'FileMusic',
        wav: 'FileMusic',
        mp4: 'FileVideo',
        mkv: 'FileVideo',
      }
      return map[ext] || 'File'
    },

    // Drag & Drop
    onDragEnter(e) {
      if (e.dataTransfer.types?.includes('Files')) {
        this.dragOver = true
      }
    },
    async onDrop(e) {
      this.dragOver = false
      const files = e.dataTransfer.files
      if (!files.length) return
      this.uploadProgress = 0
      for (const file of files) {
        let uploadFile = file
        let newFilename = null
        let overwrite = false

        if (this.items.some(i => i.name === file.name)) {
          const action = await window.showConfirm({ 
            message: `"${file.name}" 已存在`, 
            type: 'warning',
            confirmText: '覆盖',
            cancelText: '取消',
            extraText: '重命名',
            showCancel: true
          })

          if (action === 'confirm') {
            overwrite = true
          } else if (action === 'extra') {
            let name = file.name
            let ext = ''
            const lastDot = name.lastIndexOf('.')
            if (lastDot > 0) {
              ext = name.substring(lastDot)
              name = name.substring(0, lastDot)
            }
            let counter = 1
            let newName = `${name}(${counter})${ext}`
            while (this.items.some(i => i.name === newName)) {
              counter++
              newName = `${name}(${counter})${ext}`
            }
            newFilename = newName
          } else {
            window.showToast(`已取消上传: ${file.name}`, 'info')
            continue
          }
        }

        try {
          await api.uploadFileWithProgress(uploadFile, this.currentPath, pct => { this.uploadProgress = pct }, overwrite, newFilename)
          window.showToast(`上传成功: ${newFilename || file.name}`, 'success')
        } catch(e) {
          window.showToast(`上传失败(${file.name}): ${e.message || e}`, 'error')
        }
      }
      this.uploadProgress = null
      this.load()
    },
  },
}
</script>

<style scoped>
.files-container { height: 100%; display: flex; flex-direction: column; gap: 16px; }

.tab-bar { display: flex; gap: 4px; background: var(--bg-card); border-radius: var(--radius-lg); padding: 4px; box-shadow: var(--shadow-sm); border: 1px solid var(--border-base); }
.tab-btn { flex: 1; border: none; background: transparent; padding: 8px 16px; border-radius: var(--radius-md); cursor: pointer; font-size: 14px; font-weight: 600; color: var(--text-secondary); display: flex; align-items: center; justify-content: center; gap: 6px; transition: all 0.2s; }
.tab-btn.active { background: var(--brand); color: white; }
.tab-btn:hover:not(.active) { background: var(--bg-hover); }

.trash-toolbar { display: flex; align-items: center; justify-content: space-between; padding: 8px 16px; border-bottom: 1px solid var(--border-base); }
.trash-count { font-size: 13px; color: var(--text-muted); }

.toolbar { 
  display: flex; 
  align-items: center; 
  justify-content: space-between; 
  background: var(--bg-card); 
  padding: 12px 20px; 
  border-radius: var(--radius-lg); 
  box-shadow: var(--shadow-sm); 
  border: 1px solid var(--border-base);
  gap: 16px;
}
.breadcrumb-wrapper { flex: 1; overflow-x: auto; scrollbar-width: none; min-width: 0; }
.breadcrumb-wrapper::-webkit-scrollbar { display: none; }

.breadcrumb-bar { display: flex; align-items: center; min-width: max-content; font-size: 14px; }
.btn-crumb { 
  border: none; 
  background: transparent; 
  padding: 8px 12px; 
  color: var(--brand); 
  cursor: pointer; 
  border-radius: var(--radius-sm); 
  transition: all 0.2s; 
  white-space: nowrap; 
  display: flex;
  align-items: center;
  gap: 8px;
  font-weight: 500;
}
.btn-crumb:hover { background: var(--bg-info); }
.btn-crumb.is-last { color: var(--text-primary); font-weight: 700; cursor: default; pointer-events: none; }
.sep { color: var(--text-quaternary); margin: 0 2px; opacity: 0.5; flex-shrink: 0; }

.toolbar-actions { display: flex; gap: 10px; flex-shrink: 0; }
.upload-progress { display: flex; align-items: center; gap: 8px; }
.progress-bar { width: 80px; height: 6px; background: var(--bg-hover); border-radius: 3px; overflow: hidden; }
.progress-fill { height: 100%; background: var(--brand); border-radius: 3px; transition: width 0.3s ease; }
.progress-text { font-size: 12px; font-weight: 700; color: var(--brand); min-width: 36px; }
.btn-tool { 
  display: flex; 
  align-items: center; 
  gap: 8px; 
  padding: 10px 16px; 
  border: 1px solid var(--border-strong); 
  background: var(--bg-card); 
  border-radius: var(--radius-md); 
  cursor: pointer; 
  font-size: 14px; 
  transition: all 0.2s; 
  color: var(--text-secondary);
  font-weight: 500;
}
.btn-tool:hover { border-color: var(--brand); color: var(--brand); background: var(--bg-info); }
.btn-tool.btn-primary { background: var(--brand); color: var(--text-inverse); border-color: var(--brand); }
.btn-tool.btn-primary:hover { opacity: 0.9; box-shadow: 0 4px 12 hsla(var(--brand-hue) var(--brand-sat) var(--brand-lit) / 0.2); }

.spinning { animation: spin 1s linear infinite; }
@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }

.error-alert { background: var(--bg-danger); border: 1px solid var(--danger-border); color: var(--danger-text); padding: 12px 16px; border-radius: var(--radius-md); display: flex; align-items: center; gap: 12px; }
.btn-close { margin-left: auto; border: none; background: transparent; cursor: pointer; font-size: 18px; color: var(--text-tertiary); }

.dropzone-overlay { position: fixed; inset: 0; z-index: 5000; background: rgba(0,0,0,0.2); display: flex; align-items: center; justify-content: center; backdrop-filter: blur(4px); }
.dropzone-content { display: flex; flex-direction: column; align-items: center; gap: 16px; padding: 60px 80px; background: white; border-radius: var(--radius-xl); box-shadow: var(--shadow-xl); border: 3px dashed var(--brand); }
.drop-icon { color: var(--brand); opacity: 0.3; }

.files-list-wrapper { 
  flex: 1; 
  background: var(--bg-card); 
  border-radius: var(--radius-lg); 
  box-shadow: var(--shadow-sm); 
  overflow: visible; 
  border: 1px solid var(--border-base);
  display: flex;
  flex-direction: column;
}
.table-container { flex: 1; overflow: auto; }
.files-table { width: 100%; border-collapse: collapse; min-width: 600px; table-layout: fixed; }
.files-table th { background: var(--bg-table-header); padding: 16px 20px; text-align: left; font-size: 13px; font-weight: 600; color: var(--text-secondary); border-bottom: 1px solid var(--border-base); user-select: none; position: sticky; top: 0; z-index: 10; }
.files-table th.sortable { cursor: pointer; transition: color .2s; }
.files-table th.sortable:hover { color: var(--brand); }
.sort-indicator { margin-left: 4px; vertical-align: middle; color: var(--brand); }
.files-table td { padding: 14px 20px; border-bottom: 1px solid var(--border-base); font-size: 14px; color: var(--text-primary); }

.col-name { width: auto; min-width: 250px; }
.col-size { width: 120px; }
.col-time { width: 180px; }
.col-actions { width: 160px; text-align: right !important; position: relative; }

.file-row { transition: background .15s, z-index 0s; position: relative; }
.file-row:hover { background: var(--bg-table-header); }
.file-row.menu-active .col-actions { overflow: visible !important; }
.file-row.menu-active { z-index: 100 !important; }

.file-main-info { display: flex; align-items: center; gap: 12px; transition: color .2s; cursor: pointer; }
.file-main-info:hover .file-name { color: var(--brand); }
.file-icon-comp { color: var(--text-tertiary); flex-shrink: 0; }
.dir-icon { color: var(--brand); opacity: 0.8; }
.file-text-wrapper { display: flex; flex-direction: column; min-width: 0; }
.file-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-weight: 500; }
.file-name.is-dir { color: var(--text-primary); }

.mobile-meta { display: none; gap: 6px; font-size: 12px; color: var(--text-tertiary); margin-top: 2px; }
.meta-sep { opacity: 0.5; }

.actions { 
  display: flex; gap: 6px; justify-content: flex-end; align-items: center; 
  transition: transform 0.4s cubic-bezier(0.2, 0.8, 0.2, 1); 
  width: 160px; position: relative;
}
.row-actions-main { display: flex; justify-content: flex-end; gap: 6px; }

.btn-icon { width: 34px; height: 34px; display: inline-flex; align-items: center; justify-content: center; border: 1px solid var(--border-strong); border-radius: var(--radius-sm); background: white; cursor: pointer; text-decoration: none; color: var(--text-secondary); transition: all 0.2s; }
.btn-icon:hover { border-color: var(--brand); color: var(--brand); box-shadow: var(--shadow-sm); transform: translateY(-1px); }
.btn-icon.btn-danger:hover { color: var(--danger); background: var(--bg-danger); border-color: var(--danger-border); }
.btn-more-trigger { display: none; }

.inline-dialog { background: var(--bg-card); width: 90vw; max-width: 400px; border-radius: var(--radius-lg); padding: 24px; box-shadow: var(--shadow-xl); }
.inline-dialog h3 { margin: 0 0 16px; font-size: 16px; color: var(--text-primary); }
.inline-dialog input { width: 100%; padding: 10px 14px; border: 1px solid var(--border-input); border-radius: var(--radius-sm); font-size: 14px; box-sizing: border-box; outline: none; }
.inline-dialog input:focus { border-color: var(--brand); box-shadow: 0 0 0 3px var(--brand-ring); }
.inline-dialog .dialog-actions { display: flex; justify-content: flex-end; gap: 12px; margin-top: 16px; }
.inline-modal-overlay { position: fixed; inset: 0; background: #0009; display: flex; align-items: center; justify-content: center; z-index: 3000; backdrop-filter: blur(8px); }

.empty-state, .loading-state { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 80px; color: var(--text-tertiary); }
.empty-icon { color: var(--border-strong); margin-bottom: 16px; opacity: 0.5; }

/* 预览选择器样式 */
.selector-options { display: flex; flex-direction: column; gap: 12px; margin-bottom: 24px; }
.selector-btn {
  display: flex; align-items: center; gap: 16px; padding: 16px;
  background: var(--bg-card); border: 1px solid var(--border-base);
  border-radius: var(--radius-md); cursor: pointer; text-align: left;
  transition: all .2s;
}
.selector-btn:hover { border-color: var(--brand); background: var(--bg-info); transform: translateY(-2px); box-shadow: var(--shadow-md); }
.opt-icon { width: 40px; height: 40px; border-radius: 10px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
.opt-text { flex: 1; }
.opt-title { font-weight: 700; font-size: 15px; color: var(--text-primary); margin-bottom: 2px; }
.opt-desc { font-size: 12px; color: var(--text-muted); line-height: 1.4; }

/* 弹出菜单样式 */
.ctx-menu-popover {
  position: absolute; right: 54px; top: 50%; z-index: 2000;
  background: white; border: 1px solid var(--border-base); border-radius: var(--radius-md);
  box-shadow: var(--shadow-lg); min-width: 160px; padding: 6px;
  transform: translateY(-50%);
  transform-origin: right center;
}
.ctx-menu-popover .ctx-item {
  display: flex; align-items: center; gap: 10px; padding: 10px 14px;
  font-size: 14px; cursor: pointer; border-radius: var(--radius-sm);
  color: var(--text-secondary); text-decoration: none; transition: .2s;
}
.ctx-menu-popover .ctx-item:hover { background: var(--bg-info); color: var(--brand); }
.ctx-menu-popover .ctx-item.danger:hover { background: var(--bg-danger); color: var(--danger); }
.ctx-divider { height: 1px; background: var(--border-base); margin: 4px 6px; }

/* 预览叠加层与对话框 */
.preview-overlay { position: fixed; inset: 0; z-index: 3000; background: rgba(0,0,0,0.6); display: flex; align-items: center; justify-content: center; backdrop-filter: blur(8px); }
.preview-dialog { background: var(--bg-card); width: 90vw; height: 85vh; max-width: 1100px; border-radius: var(--radius-lg); display: flex; flex-direction: column; overflow: hidden; box-shadow: var(--shadow-xl); border: 1px solid var(--glass-border); position: relative; }
.preview-header { display: flex; justify-content: space-between; align-items: center; padding: 16px 24px; border-bottom: 1px solid var(--border-base); background: #fafafa; }
.preview-header h3 { margin: 0; font-size: 16px; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.btn-close-preview { border: none; background: transparent; cursor: pointer; color: var(--text-tertiary); padding: 4px; border-radius: 50%; display: flex; transition: .2s; }
.btn-close-preview:hover { background: var(--bg-hover); color: var(--text-primary); transform: rotate(90deg); }
.preview-body { flex: 1; overflow: hidden; background: #f0f0f0; display: flex; align-items: center; justify-content: center; }
.preview-iframe { width: 100%; height: 100%; border: none; background: white; }
.img-viewport { width: 100%; height: 100%; overflow: hidden; display: flex; align-items: center; justify-content: center; position: relative; }
.preview-img { max-width: 95%; max-height: 95%; cursor: grab; user-select: none; transition: transform 0.1s ease-out; filter: drop-shadow(0 10px 30px rgba(0,0,0,0.1)); }
.preview-img.dragging { cursor: grabbing; transition: none; }
.img-zoom-bar { position: absolute; bottom: 24px; left: 50%; transform: translateX(-50%); background: rgba(0,0,0,0.7); border-radius: 30px; display: flex; align-items: center; gap: 4px; padding: 6px 12px; backdrop-filter: blur(8px); z-index: 10; }
.zoom-btn { border: none; background: transparent; color: #fff; width: 32px; height: 32px; border-radius: 50%; cursor: pointer; font-size: 18px; display: flex; align-items: center; justify-content: center; transition: background-color .2s; }
.zoom-btn:hover { background: rgba(255,255,255,0.2); }
.zoom-label { color: #fff; font-size: 13px; min-width: 50px; text-align: center; font-weight: 500; }
.preview-footer { padding: 16px 24px; border-top: 1px solid var(--border-base); background: #fafafa; display: flex; justify-content: flex-end; gap: 12px; }

/* Text editor */
.editor-dialog { max-width: 1200px; }
.editor-header-actions { display: flex; align-items: center; gap: 6px; }
.btn-icon-soft { border: 1px solid transparent; background: transparent; color: var(--text-secondary); width: 32px; height: 32px; border-radius: 8px; display: inline-flex; align-items: center; justify-content: center; cursor: pointer; }
.btn-icon-soft:hover, .btn-icon-soft.active { background: var(--bg-info); color: var(--brand); border-color: var(--border-base); }
.editor-body { flex: 1; min-height: 0; background: #fff; overflow: auto; }
.editor-body.wrap-lines { overflow-x: hidden; }
.code-view, .code-textarea { margin: 0; padding: 20px 24px; font: 13px/1.7 Consolas, "Cascadia Code", monospace; tab-size: 4; white-space: pre; overflow: auto; min-height: 100%; box-sizing: border-box; }
.editor-body.wrap-lines .code-view, .editor-body.wrap-lines .code-textarea { white-space: pre-wrap; overflow-wrap: anywhere; }
.code-textarea { width: 100%; height: 100%; border: 0; outline: none; resize: none; background: #fff; color: var(--text-primary); }
.editor-footer { align-items: center; }
.editor-meta { margin-right: auto; color: var(--text-tertiary); font-size: 12px; }
.code-view .hljs { background: transparent; padding: 0; }

/* Archive browser */
.archive-dialog { max-width: 1200px; }
.archive-toolbar { display: flex; align-items: center; gap: 12px; padding: 10px 20px; border-bottom: 1px solid var(--border-base); background: #fafafa; }
.archive-filter { flex: 1; min-width: 120px; padding: 8px 12px; border: 1px solid var(--border-base); border-radius: 8px; outline: none; }
.archive-count, .archive-lock { color: var(--text-tertiary); font-size: 12px; display: inline-flex; align-items: center; gap: 4px; }
.archive-body { flex: 1; min-height: 0; display: flex; background: #fff; }
.archive-list { width: 42%; max-width: 460px; overflow: auto; border-right: 1px solid var(--border-base); background: #fafafa; }
.archive-entry { display: flex; align-items: center; gap: 8px; padding: 9px 14px; cursor: pointer; font-size: 13px; border-bottom: 1px solid rgba(0,0,0,0.04); }
.archive-entry:hover { background: #f0f7ff; }
.archive-entry.selected { background: var(--bg-info); color: var(--brand); }
.archive-entry.dir { font-weight: 600; }
.archive-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.archive-size { color: var(--text-tertiary); font-size: 11px; flex-shrink: 0; }
.entry-lock { color: var(--warning); flex-shrink: 0; }
.archive-preview { flex: 1; overflow: auto; min-width: 0; }
.archive-text { margin: 0; padding: 16px 20px; font: 13px/1.65 Consolas, monospace; white-space: pre-wrap; overflow-wrap: anywhere; }
.archive-image { max-width: 100%; max-height: 100%; object-fit: contain; display: block; margin: auto; }
.archive-placeholder { height: 100%; display: flex; align-items: center; justify-content: center; color: var(--text-tertiary); font-size: 14px; }
.archive-password-overlay { position: absolute; inset: 0; background: rgba(0,0,0,0.45); display: flex; align-items: center; justify-content: center; z-index: 2; }
.archive-password-box { width: 380px; max-width: 90%; padding: 22px; border-radius: var(--radius-lg); background: var(--bg-card); }
.archive-password-box h4 { margin: 0 0 10px; display: flex; align-items: center; gap: 8px; }
.archive-password-box p { color: var(--text-secondary); font-size: 13px; line-height: 1.6; margin: 0 0 14px; }
.archive-password-input { width: 100%; padding: 10px 12px; border: 1px solid var(--border-base); border-radius: 8px; box-sizing: border-box; }

/* Contact / calendar card */
.card-dialog { max-width: 640px; height: auto; max-height: 88vh; }
.card-body { display: block; background: #fff; overflow: auto; }
.card-form { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; padding: 22px 26px; }
.card-form label { display: flex; flex-direction: column; gap: 6px; font-size: 12px; font-weight: 600; color: var(--text-secondary); }
.card-form label.full { grid-column: 1 / -1; }
.card-form input, .card-form textarea { padding: 9px 11px; border: 1px solid var(--border-base); border-radius: 8px; font-size: 13px; font-family: inherit; box-sizing: border-box; resize: vertical; }
.card-form input:focus, .card-form textarea:focus { outline: none; border-color: var(--brand); }

.pop-enter-active, .pop-leave-active { transition: all 0.25s cubic-bezier(0.34, 1.56, 0.64, 1); }
.pop-enter-from, .pop-leave-to { opacity: 0; transform: translateY(-50%) scale(0.9) translateX(10px); }

.list-move, .list-enter-active { transition: all 0.3s ease; }
.list-enter-from { opacity: 0; transform: translateX(-10px); }
.list-leave-active { transition: opacity 0.25s ease; }
.list-leave-to { opacity: 0; }

@media (max-width: 768px) {
  .hide-mobile { display: none !important; }
  .mobile-meta { display: flex; }
  .toolbar { padding: 10px 16px; gap: 8px; flex-direction: column; align-items: stretch; }
  .breadcrumb-wrapper { width: 100%; overflow-x: auto; }
  
  .files-table { min-width: 0 !important; width: 100% !important; display: block; }
  .files-table thead { display: none !important; }
  .files-table tbody { display: block; width: 100%; }

  .file-row { position: relative; overflow: visible; display: flex; background: var(--bg-card); border-radius: var(--radius-md); margin-bottom: 8px; border: 1px solid var(--border-base); align-items: center; width: 100%; box-sizing: border-box; }
  .file-row td { display: block; border: none; padding: 12px; vertical-align: middle; }
  .col-name { flex: 1; min-width: 0; overflow: hidden; }
  .col-size, .col-time { display: none !important; }
  .file-name { font-weight: 700; font-size: 15px; }
  
  .col-actions { 
    display: flex; align-items: center; justify-content: center; width: 48px; height: 100%; padding: 0;
    border-left: 1px solid var(--border-base); background: #fafafa; flex: 0 0 48px !important;
    position: relative; overflow: hidden;
  }
  .file-row.swipe-open .col-actions,
  .file-row.menu-active .col-actions { overflow: visible !important; }
  .btn-more-trigger { display: inline-flex; border: none; background: transparent; color: var(--text-tertiary); }
  
  /* 移动端专属侧滑层 */
  .row-actions-main { 
    position: absolute; right: 0; top: 0; bottom: 0; width: 160px; 
    background: var(--bg-card); display: flex; gap: 8px; padding: 0 12px; 
    border-left: 1px solid var(--brand); box-shadow: -4px 0 12px rgba(0,0,0,0.05); 
    z-index: 10; align-items: center;
    transform: translateX(calc(100% + 8px));
    transition: transform 0.4s cubic-bezier(0.2, 0.8, 0.2, 1);
  }
  .file-row.swipe-open .row-actions-main { transform: translateX(0); }
  .file-row.swipe-open .btn-more-trigger { opacity: 0; pointer-events: none; }

  .btn-icon { width: 42px; height: 42px; }
  .preview-dialog { height: 95vh; width: 100vw; border-radius: 0; }
}

@media (max-width: 1024px) {
  .hide-tablet { display: none !important; }
}
</style>
