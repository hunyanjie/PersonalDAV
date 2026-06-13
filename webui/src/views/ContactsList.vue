<template>
  <div class="contacts-page">
    <div class="toolbar glass">
      <div class="search-box">
        <Search :size="18" class="search-icon" />
        <input v-model="query" placeholder="搜索姓名、邮箱或电话..." @input="debounceSearch" class="search-input" />
      </div>
      <div class="toolbar-actions">
        <label class="btn-tool btn-import">
          <Upload :size="18" /> <span class="hide-mobile">导入 .vcf</span>
          <input type="file" accept=".vcf,.vcard" @change="doImport" hidden />
        </label>
        <router-link to="/contacts/new" class="btn-tool btn-primary">
          <Plus :size="18" /> <span class="hide-mobile">新建联系人</span>
        </router-link>
      </div>
    </div>

    <div class="list-wrapper glass">
      <div v-if="items.length" class="table-scroll">
        <table class="data-table">
          <thead>
            <tr>
              <th><div class="th-inner"><User :size="14" /> 姓名</div></th>
              <th class="hide-mobile"><div class="th-inner"><Mail :size="14" /> 邮箱</div></th>
              <th class="hide-tablet"><div class="th-inner"><Phone :size="14" /> 电话</div></th>
              <th class="hide-tablet"><div class="th-inner"><Tag :size="14" /> 分组</div></th>
              <th class="col-actions">操作</th>
            </tr>
          </thead>
          <transition-group tag="tbody" name="list">
            <tr v-for="c in items" :key="c.uid" class="contact-row"
              :class="{ 'swipe-open': _swipeUid === c.uid, 'menu-active': _menuUid === c.uid }"
              @touchstart="swipeStart(c.uid, $event)"
              @touchmove="swipeMove($event)"
              @touchend="swipeEnd(c.uid)">
              <td class="col-name">
                <div class="name-info" @click="closeSwipe">
                  <span class="avatar">{{ (c.full_name || '?')[0].toUpperCase() }}</span>
                  <div class="name-text">
                    <span class="full-name">{{ c.full_name }}</span>
                    <span class="mobile-only-info">{{ c.phone || c.email }}</span>
                  </div>
                </div>
              </td>
              <td class="col-email hide-mobile">{{ c.email || '-' }}</td>
              <td class="col-phone hide-tablet">{{ c.phone || '-' }}</td>
              <td class="hide-tablet">
                <div class="groups-list">
                  <span v-for="g in splitGroups(c.groups)" :key="g" class="group-tag">{{ g }}</span>
                </div>
              </td>
              <td class="actions">
                <!-- 始终可见的三个点按钮 (对标文件页面) -->
                <button class="btn-icon btn-more-trigger" @click.stop="toggleMenu(c.uid)" title="更多">
                  <MoreHorizontal :size="20" />
                </button>
                
                <!-- 仅在侧滑或桌面端显示的按钮组 -->
                <div class="row-actions-main" :style="swipeStyle(c.uid)">
                  <button class="btn-icon" @touchstart.stop @click.stop="doExport(c)" title="导出 VCF"><ArrowDownToLine :size="16" /></button>
                  <router-link :to="`/contacts/${c.uid}/edit`" class="btn-icon" title="编辑" @touchstart.stop @click.stop><Pencil :size="16" /></router-link>
                  <button class="btn-icon btn-danger" @touchstart.stop @click.stop="doDelete(c.uid)" title="删除"><Trash2 :size="16" /></button>
                </div>

                <!-- 弹出式菜单 (层级修正) -->
                <transition name="pop">
                  <div v-if="_menuUid === c.uid" class="ctx-menu-popover glass" @click.stop>
                    <div class="ctx-item" @click="doExport(c); _menuUid = null"><ArrowDownToLine :size="16" /> 导出 VCF</div>
                    <router-link :to="`/contacts/${c.uid}/edit`" class="ctx-item" @click="_menuUid = null"><Pencil :size="16" /> 编辑信息</router-link>
                    <div class="ctx-divider" />
                    <div class="ctx-item danger" @click="doDelete(c.uid); _menuUid = null"><Trash2 :size="16" /> 删除联系人</div>
                  </div>
                </transition>
              </td>
            </tr>
          </transition-group>
        </table>
      </div>
      <div v-else class="empty-state">
        <div class="empty-icon"><Users :size="48" /></div>
        <p>{{ loading ? '正在加载...' : '暂无联系人' }}</p>
      </div>
    </div>

    <div v-if="total > pageSize" class="pagination-bar glass">
      <div class="page-info hide-mobile">
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
  ChevronLeft, ChevronRight, MoreHorizontal
} from 'lucide-vue-next'
import api from '../api.js'

export default {
  components: { 
    Search, Upload, Plus, User, Mail, Phone, Tag, 
    ArrowDownToLine, Pencil, Trash2, Users,
    ChevronLeft, ChevronRight, MoreHorizontal
  },
  data: () => ({ 
    items: [], query: '', page: 0, pageSize: 50, total: 0, 
    loading: false, _timer: null, pageInput: 1, localPageSize: 50,
    _swipeUid: null, _swipeOffset: 0, _swipeStartX: 0, _swipeStartY: 0,
    _menuUid: null, _isDragging: false,
  }),
  computed: {
    maxPage() { return Math.max(1, Math.ceil(this.total / this.pageSize)) },
  },
  watch: { 
    page() { this.pageInput = this.page + 1; this.load() } 
  },
  async mounted() { 
    this.load()
    document.addEventListener('click', this._closeMenu)
  },
  beforeUnmount() { 
    document.removeEventListener('click', this._closeMenu) 
  },
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
    swipeStart(uid, e) {
      if (window.innerWidth > 768) return
      if (this._swipeUid === uid && this._swipeOffset === 140) return
      if (e.target.closest('.actions, .btn-more-trigger, .ctx-menu-popover')) return
      this._swipeUid = uid
      this._swipeStartX = e.touches[0].clientX
      this._swipeStartY = e.touches[0].clientY
      this._swipeOffset = 0
      this._isDragging = false
    },
    swipeMove(e) {
      if (!this._swipeUid) return
      const dx = this._swipeStartX - e.touches[0].clientX
      const dy = Math.abs(this._swipeStartY - e.touches[0].clientY)
      if (dy > 40) { this.closeSwipe(); return }
      
      if (Math.abs(dx) > 30) {
        this._isDragging = true
        e.stopPropagation()
        this._swipeOffset = Math.max(0, Math.min(140, dx))
      }
    },
    swipeEnd(uid) {
      const wasDragging = this._isDragging
      this._isDragging = false
      if (this._swipeUid !== uid) return
      
      if (wasDragging && this._swipeOffset > 70) {
        this._swipeOffset = 140
      } else if (wasDragging) {
        this.closeSwipe()
      }
    },
    closeSwipe() { this._swipeUid = null; this._swipeOffset = 0; this._isDragging = false },
    toggleMenu(uid) { this._menuUid = this._menuUid === uid ? null : uid },
    _closeMenu() { this._menuUid = null },
    swipeStyle(uid) {
      if (window.innerWidth > 768) return {}
      if (this._swipeUid !== uid) return { transform: 'translateX(100%)' }
      const offset = 140 - this._swipeOffset
      const style = { transform: `translateX(${offset}px)` }
      if (this._isDragging) style.transition = 'none'
      else style.transition = 'transform 0.4s cubic-bezier(0.2, 0.8, 0.2, 1)'
      return style
    },
    async doImport(e) {
      const file = e.target.files[0]
      if (!file) return
      try {
        const text = await file.text()
        const blocks = text.split(/(?=BEGIN:VCARD)/).filter(Boolean)
        for (const block of blocks) {
          try { await api.createContact(block.trim()) } catch(e) {}
        }
        this.load()
      } catch(e) { window.showToast('导入失败', 'error') }
      e.target.value = ''
    },
    async doDelete(uid) {
      if (!await window.showConfirm({ message: '确认删除该联系人？', type: 'danger' })) return
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
      } catch(e) { window.showToast('导出失败', 'error') }
    },
  },
}
</script>

<style scoped>
.contacts-page { height: 100%; display: flex; flex-direction: column; gap: 16px; }

.toolbar { 
  display: flex; 
  flex-wrap: wrap;
  gap: 16px; 
  background: var(--bg-card); 
  padding: 12px 20px; 
  border-radius: var(--radius-lg); 
  box-shadow: var(--shadow-sm); 
  border: 1px solid var(--border-base);
  align-items: center;
}
.search-box { flex: 1 1 0; position: relative; min-width: 140px; }
.search-icon { position: absolute; left: 12px; top: 50%; transform: translateY(-50%); color: var(--text-tertiary); }
.search-input { 
  width: 100%; 
  padding: 12px 12px 12px 42px; 
  border: 1px solid var(--border-input); 
  border-radius: var(--radius-md); 
  font-size: 14px; 
  transition: all .2s;
  background: #fafafa;
  outline: none;
  box-sizing: border-box;
}
.search-input:focus { border-color: var(--brand); background: white; box-shadow: 0 0 0 3px var(--brand-ring); }

.toolbar-actions { display: flex; gap: 10px; flex-shrink: 0; }
.btn-tool { 
  display: flex; 
  align-items: center; 
  gap: 8px; 
  padding: 10px 18px; 
  border: 1px solid var(--border-strong); 
  background: var(--bg-card); 
  border-radius: var(--radius-md); 
  cursor: pointer; 
  font-size: 14px; 
  transition: all 0.2s; 
  text-decoration: none;
  color: var(--text-secondary);
  font-weight: 600;
}
.btn-tool:hover { border-color: var(--brand); color: var(--brand); background: var(--bg-info); transform: translateY(-1px); }
.btn-tool.btn-primary { background: var(--brand); color: var(--text-inverse); border-color: var(--brand); }

.list-wrapper { 
  flex: 1; 
  background: var(--bg-card); 
  border-radius: var(--radius-lg); 
  box-shadow: var(--shadow-sm); 
  overflow: visible; 
  border: 1px solid var(--border-base);
  display: flex;
  flex-direction: column;
}
.table-scroll { flex: 1; overflow: auto; }
.data-table { width: 100%; border-collapse: collapse; min-width: 500px; table-layout: fixed; }
.data-table th { background: var(--bg-table-header); padding: 16px 20px; text-align: left; border-bottom: 1px solid var(--border-base); font-size: 13px; color: var(--text-secondary); font-weight: 700; position: sticky; top: 0; z-index: 10; }
.th-inner { display: flex; align-items: center; gap: 8px; }
.data-table td { padding: 14px 20px; border-bottom: 1px solid var(--border-base); font-size: 14px; color: var(--text-primary); }

.contact-row { transition: background .15s, z-index 0s; position: relative; }
.contact-row:hover { background: var(--bg-table-header); }
.contact-row.menu-active { z-index: 100 !important; }

.name-info { display: flex; align-items: center; gap: 12px; }
.avatar { width: 36px; height: 36px; background: var(--brand); color: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 16px; flex-shrink: 0; box-shadow: 0 4px 8px var(--brand-ring); }
.name-text { display: flex; flex-direction: column; min-width: 0; }
.full-name { font-weight: 700; color: var(--text-primary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.mobile-only-info { display: none; font-size: 12px; color: var(--text-tertiary); font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.groups-list { display: flex; flex-wrap: wrap; gap: 6px; }
.group-tag { 
  background: var(--bg-info); 
  color: var(--brand); 
  padding: 3px 10px; 
  border-radius: 20px; 
  font-size: 11px; 
  font-weight: 700;
  border: 1px solid hsla(var(--brand-hue), var(--brand-sat), var(--brand-lit), 0.1);
}

.actions { display: flex; gap: 6px; justify-content: flex-end; position: relative; align-items: center; width: 140px; }
.row-actions-main { display: flex; gap: 6px; }
.btn-more-trigger { display: none; }
.btn-icon { width: 34px; height: 34px; display: inline-flex; align-items: center; justify-content: center; border: 1px solid var(--border-strong); border-radius: var(--radius-sm); background: white; cursor: pointer; text-decoration: none; color: var(--text-secondary); transition: all 0.2s; }
.btn-icon:hover { border-color: var(--brand); color: var(--brand); box-shadow: var(--shadow-sm); transform: translateY(-1px); }
.btn-icon.btn-danger:hover { color: var(--danger); background: var(--bg-danger); border-color: var(--danger-border); }

.empty-state { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 100px 0; color: var(--text-tertiary); }
.empty-icon { opacity: 0.2; margin-bottom: 20px; }

.pagination-bar { 
  display: flex; 
  align-items: center; 
  justify-content: space-between; 
  padding: 12px 24px; 
  background: var(--bg-card); 
  border-radius: var(--radius-lg); 
  box-shadow: var(--shadow-sm); 
  border: 1px solid var(--border-base);
  margin-top: 8px;
}
.page-info { font-size: 13px; color: var(--text-secondary); }
.page-controls { display: flex; align-items: center; gap: 12px; }
.btn-page { width: 36px; height: 36px; display: flex; align-items: center; justify-content: center; border: 1px solid var(--border-strong); border-radius: 50%; background: white; cursor: pointer; transition: .2s; }
.btn-page:hover:not(:disabled) { border-color: var(--brand); color: var(--brand); transform: scale(1.1); }
.btn-page:disabled { opacity: 0.3; cursor: not-allowed; }

.page-jump-box { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 700; }
.page-input { width: 50px; padding: 6px; border: 1px solid var(--border-input); border-radius: 6px; text-align: center; font-weight: 700; outline: none; }
.page-input:focus { border-color: var(--brand); }
.page-size-select { padding: 8px 12px; border-radius: var(--radius-sm); border: 1px solid var(--border-strong); font-size: 13px; background: white; font-weight: 600; cursor: pointer; }

/* 弹出式菜单样式 */
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

/* 动画 */
.pop-enter-active, .pop-leave-active { transition: all 0.25s cubic-bezier(0.34, 1.56, 0.64, 1); }
.pop-enter-from, .pop-leave-to { opacity: 0; transform: translateY(-50%) scale(0.9) translateX(10px); }

.list-move, .list-enter-active, .list-leave-active { transition: all 0.3s ease; }
.list-enter-from, .list-leave-to { opacity: 0; transform: translateX(-10px); }
.list-leave-active { position: absolute; }

@media (max-width: 1100px) {
  .toolbar { flex-direction: column; align-items: stretch; }
  .search-box { min-width: 100%; }
  .toolbar-actions { width: 100%; justify-content: flex-end; }
}
@media (max-width: 768px) {
  .hide-mobile { display: none !important; }
  .mobile-only-info { display: block; }
  .toolbar { padding: 12px; flex-direction: column; align-items: stretch; gap: 12px; }
  .search-box { width: 100%; min-width: 100%; order: 1; }
  .toolbar-actions { width: 100%; justify-content: space-between; order: 2; gap: 8px; }
  .btn-tool { flex: 1; justify-content: center; padding: 10px 12px; font-size: 13px; }
  
  .data-table { min-width: 0; display: block; width: 100%; }
  .data-table thead { display: none; }
  .data-table tbody { display: block; width: 100%; }
  .data-table th.col-actions { display: none; }

  .contact-row { position: relative; overflow: visible; display: flex; background: var(--bg-card); border-radius: var(--radius-md); margin-bottom: 8px; border: 1px solid var(--border-base); align-items: center; width: 100%; box-sizing: border-box; }
  .contact-row td { display: block; border: none; padding: 12px; flex: 1; min-width: 0; }
  .col-name { flex: 1; min-width: 0; }
  .col-email, .col-phone, .hide-tablet { display: none !important; }
  
  .actions { 
    display: flex; align-items: center; justify-content: center; width: 48px; height: 100%; padding: 0;
    border-left: 1px solid var(--border-base); background: #fafafa; flex: 0 0 48px !important;
    position: relative; overflow: hidden;
  }
  .contact-row.swipe-open .actions,
  .contact-row.menu-active .actions { overflow: visible !important; }
  .btn-more-trigger { display: inline-flex; border: none; background: transparent; color: var(--text-tertiary); }
  
  /* 移动端专属侧滑层 */
  .row-actions-main { 
    position: absolute; right: 0; top: 0; bottom: 0; width: 140px; 
    background: var(--bg-card); display: flex; gap: 8px; padding: 0 12px; 
    border-left: 1px solid var(--brand); box-shadow: -4px 0 12px rgba(0,0,0,0.05); 
    z-index: 10; align-items: center;
    transform: translateX(calc(100% + 8px)); /* 默认隐藏在屏幕右侧 */
    transition: transform 0.4s cubic-bezier(0.2, 0.8, 0.2, 1);
  }
  .contact-row.swipe-open .row-actions-main { transform: translateX(0); }
  .contact-row.swipe-open .btn-more-trigger { opacity: 0; pointer-events: none; }

  .btn-icon { width: 42px; height: 42px; }
  .ctx-menu-popover { right: 54px; top: 12px; }
  
  .pagination-bar { padding: 16px 12px; flex-direction: column; gap: 16px; align-items: center; }
  .page-info { order: 3; }
  .page-controls { order: 1; width: 100%; justify-content: center; }
  .page-size-select { order: 2; width: 100%; }
}
</style>
