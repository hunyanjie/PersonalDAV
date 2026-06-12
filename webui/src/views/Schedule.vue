<template>
  <div class="agenda-container">
    <div class="agenda-list-side">
      <div class="agenda-header">
        <div class="ah-left">
          <span class="ah-title">{{ currentYearMonth }}</span>
          <span class="ah-week">第 {{ currentWeek }} 周</span>
        </div>
        <button class="btn-create" @click="createForFloatingDate">+ 新建日程</button>
      </div>

      <div class="scroll-viewport" ref="listRef" @scroll="onScroll">
        <div class="floating-date-header" v-if="stickyHeader">
          <div class="fh-left">
            <span class="fh-date">{{ stickyHeader.label }}</span>
            <span class="fh-weekday">{{ stickyHeader.weekday }}</span>
          </div>
          <div class="fh-right">{{ stickyHeader.lunar }}</div>
        </div>
        <div class="virtual-list" :style="{ height: totalHeight + 'px' }">
          <div v-for="item in visibleItems" :key="item.key"
            class="list-item"
            :class="{ 'type-header': item.type === 'header', 'type-event': item.type === 'event', 'type-empty': item.type === 'empty', 'is-selected': isSelected(item) }"
            :style="{ transform: `translateY(${item.top}px)` }"
            @click="onItemClick(item, $event)"
            @contextmenu.prevent="onCtxMenu(item, $event)">
            
            <template v-if="item.type === 'header'">
              <div class="date-header">
                <div class="dh-left">
                  <span class="dh-date">{{ item.label }}</span>
                  <span class="dh-weekday">{{ item.weekday }}</span>
                </div>
                <div class="dh-right">{{ item.lunar }}</div>
              </div>
            </template>

            <template v-else-if="item.type === 'nowbar'">
              <div class="now-bar-wrapper"><div class="now-bar-line" /></div>
            </template>

            <template v-else-if="item.type === 'event'">
              <div class="event-card-wrapper">
                <div class="card-side-bar" :style="cardSideStyle(item)"></div>
                <div class="card-content">
                  <div class="card-main">
                    <div class="card-title" :class="{ 'is-ended': item.status === 'ended' }">
                      <span class="title-text">{{ item.summary || '(无标题)' }}</span>
                    </div>
                    <div class="card-time" :class="{ 'is-ended': item.status === 'ended' }">{{ item.range }}</div>
                  </div>
                  <div v-if="item.description" class="card-desc" :class="{ 'is-ended': item.status === 'ended' }">
                    {{ item.description }}
                  </div>
                </div>
              </div>
            </template>

            <template v-else-if="item.type === 'empty'">
              <div class="empty-day">今日无日程</div>
            </template>
          </div>
        </div>
        <div v-if="loading" class="list-loading">加载中...</div>
      </div>
    </div>

    <div class="agenda-detail-side">
      <div v-if="selectedEvent" class="detail-box">
        <div class="detail-header">
          <h2>{{ selectedEvent.summary || '(无标题)' }}</h2>
          <div class="detail-meta">
            <span class="meta-tag">{{ selectedEvent.categories || '默认' }}</span>
          </div>
        </div>
        <div class="detail-body">
          <div class="detail-row">
            <i class="icon">🕒</i>
            <div class="row-val">
              <div class="time-range">{{ fmtTime(selectedEvent.dtstart) }} - {{ fmtTime(selectedEvent.dtend) }}</div>
              <div class="date-val">{{ fmtFullDate(selectedEvent.dtstart) }}</div>
            </div>
          </div>
          <div v-if="selectedEvent.location" class="detail-row">
            <i class="icon">📍</i>
            <div class="row-val">{{ selectedEvent.location }}</div>
          </div>
          <div v-if="selectedEvent.description" class="detail-row">
            <i class="icon">📝</i>
            <div class="row-val desc-text">{{ selectedEvent.description }}</div>
          </div>
        </div>
        <div class="detail-footer">
          <button class="btn-action" @click="exportSingle(selectedEvent)">分享/导出</button>
          <button class="btn-action" @click="startEdit(selectedEvent)">编辑</button>
          <button class="btn-action btn-danger" @click="deleteSingle(selectedEvent)">删除</button>
        </div>
      </div>
      <div v-else-if="selectedUids.length > 1" class="detail-empty">
        <div class="empty-icon">👥</div>
        <p>选择了 {{ selectedUids.length }} 个日程</p>
        <button class="btn-action" @click="exportSelected">批量导出</button>
        <button class="btn-action btn-danger" @click="deleteSelected">批量删除</button>
      </div>
      <div v-else class="detail-empty">
        <div class="empty-icon">📅</div>
        <p>选择日程查看详情</p>
      </div>
    </div>

    <!-- Edit Modal -->
    <div v-if="editModal" class="modal-overlay" @click.self="editModal = null">
      <div class="modal-card">
        <div class="modal-header">
          <h3>{{ editModal.isNew ? '新建日程' : '编辑日程' }}</h3>
          <button class="btn-close" @click="editModal = null">&times;</button>
        </div>
        <div class="modal-body">
          <div class="form-group">
            <label>标题</label>
            <input v-model="editForm.summary" placeholder="日程标题" />
          </div>
          <div class="form-row">
            <div class="form-group">
              <label>开始时间</label>
              <input v-model="editForm.dtstart" type="datetime-local" />
            </div>
            <div class="form-group">
              <label>结束时间</label>
              <input v-model="editForm.dtend" type="datetime-local" />
            </div>
          </div>
          <div class="form-group">
            <label>地点</label>
            <input v-model="editForm.location" placeholder="添加地点" />
          </div>
          <div class="form-group">
            <label>描述</label>
            <textarea v-model="editForm.description" rows="4" placeholder="添加描述..."></textarea>
          </div>
          <div class="form-group">
            <label>分类</label>
            <input v-model="editForm.categories" placeholder="用逗号分隔" />
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn-cancel" @click="editModal = null">取消</button>
          <button class="btn-save" @click="saveEdit" :disabled="saving">
            {{ saving ? '保存中...' : '保存' }}
          </button>
        </div>
      </div>
    </div>

    <!-- Context Menu -->
    <div v-if="ctxMenu.show" class="ctx-menu" :style="{ top: ctxMenu.y + 'px', left: ctxMenu.x + 'px' }" @click.stop>
      <div class="ctx-item" @click="exportSelected">分享/导出</div>
      <div class="ctx-item" @click="startEdit(eventsMap[ctxMenu.uids[0]])" v-if="ctxMenu.uids.length === 1">编辑</div>
      <div class="ctx-item danger" @click="deleteSelected">删除</div>
    </div>
  </div>
</template>

<script>
import api from '../api.js'

function pad(n) { return String(n).padStart(2, '0') }

function icalDateToObj(s) {
  if (!s) return null
  const m = s.match(/^(\d{4})-?(\d{2})-?(\d{2})[T ]?(\d{2}):?(\d{2})?(:\d{2})?/)
  if (!m) return null
  return new Date(+m[1], +m[2] - 1, +m[3], +m[4] || 0, +(m[5] || 0), 0)
}

function icalToDatetimeLocal(s) {
  if (!s) return ''
  const o = icalDateToObj(s)
  if (!o) return ''
  return `${o.getFullYear()}-${pad(o.getMonth()+1)}-${pad(o.getDate())}T${pad(o.getHours())}:${pad(o.getMinutes())}`
}

function fmtDate(d) {
  if (typeof d === 'string') {
    const o = icalDateToObj(d)
    if (!o) return ''
    return `${o.getFullYear()}-${pad(o.getMonth() + 1)}-${pad(o.getDate())}`
  }
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
}

function fmtTime(s) {
  const d = icalDateToObj(s)
  if (!d) return s || ''
  const h = d.getHours(), m = pad(d.getMinutes())
  const ampm = h < 12 ? '上午' : '下午'
  const h12 = h === 0 ? 12 : (h > 12 ? h - 12 : h)
  return `${ampm} ${h12}:${m}`
}

function getLunar(dStr) {
  // A very simple placeholder or logic for lunar calendar
  // Since we don't have a library, we'll just return an empty string or a static label for now
  // In a real app, we'd use lunar-javascript or similar.
  return '' 
}

function weekNumber(d) {
  const s = new Date(d.getFullYear(), 0, 1)
  const diff = d - s + (s.getTimezoneOffset() - d.getTimezoneOffset()) * 60000
  return Math.ceil((diff / 86400000 + s.getDay() + 1) / 7)
}

function eventStatus(e, now) {
  const st = icalDateToObj(e.dtstart)
  const et = icalDateToObj(e.dtend)
  if (!st || !et) return 'upcoming'
  if (now >= et) return 'ended'
  if (now >= st) return 'ongoing'
  return 'upcoming'
}

const WEEKDAY_NAMES = ['日', '一', '二', '三', '四', '五', '六']
const HEADER_HEIGHT = 48
const ITEM_HEIGHT = 80
const EMPTY_HEIGHT = 40
const OVERSCAN = 15

export default {
  data: () => ({
    events: [],
    loading: false,
    saving: false,
    scrollTop: 0,
    containerHeight: 800,
    selectedUids: [],
    editModal: null,
    editForm: { summary: '', dtstart: '', dtend: '', location: '', description: '', categories: '' },
    ctxMenu: { show: false, x: 0, y: 0, uids: [] },
    currentTime: new Date(),
    _nowTimer: null,
    _mounted: false,
    _loadingInitial: false,
    _loadStart: '2000-01-01',
    _loadEnd: '2099-12-31',
  }),
  computed: {
    grouped() {
      const groups = {}
      const today = fmtDate(this.currentTime)
      for (const e of this.events) {
        const start = fmtDate(e.dtstart)
        const end = fmtDate(e.dtend) || start
        if (!start) continue
        let d = new Date(start)
        const endD = new Date(end)
        while (d <= endD) {
          const ds = fmtDate(d)
          if (!groups[ds]) groups[ds] = { date: ds, events: [] }
          if (!groups[ds].events.find(x => x.uid === e.uid))
            groups[ds].events.push(e)
          d.setDate(d.getDate() + 1)
        }
      }
      const keys = Object.keys(groups).sort()
      const result = []
      for (const k of keys) {
        const g = groups[k]
        g.events.sort((a, b) => (a.dtstart || '').localeCompare(b.dtstart || ''))
        if (k === today || g.events.length > 0) result.push(g)
      }
      if (!result.find(g => g.date === today)) {
        result.push({ date: today, events: [] })
        result.sort((a, b) => a.date.localeCompare(b.date))
      }
      return result
    },
    eventsMap() {
      const m = {}
      for (const e of this.events) m[e.uid] = e
      return m
    },
    virtualItems() {
      const items = []
      const now = this.currentTime
      const todayStr = fmtDate(now)
      const secondsPast = now.getHours() * 3600 + now.getMinutes() * 60 + now.getSeconds()
      const daySeconds = 86400
      let top = 0
      for (const g of this.grouped) {
        const dt = icalDateToObj(g.date + 'T00:00:00')
        const wd = dt ? WEEKDAY_NAMES[dt.getDay()] : ''
        const label = `${parseInt(g.date.split('-')[1])}月${parseInt(g.date.split('-')[2])}日`
        items.push({ type: 'header', key: 'h-' + g.date, top, height: HEADER_HEIGHT, dateStr: g.date, label, weekday: '周' + wd, lunar: getLunar(g.date) })
        top += HEADER_HEIGHT
        if (g.date === todayStr && g.events.length > 0) {
          const nowY = top + (secondsPast / daySeconds) * (g.events.length * ITEM_HEIGHT + 4)
          items.push({ type: 'nowbar', key: 'now-' + g.date, top: nowY, height: 2, dateStr: g.date })
        }
        if (!g.events.length) {
          items.push({ type: 'empty', key: 'e-' + g.date, top, height: EMPTY_HEIGHT, dateStr: g.date })
          top += EMPTY_HEIGHT
        }
        for (const e of g.events) {
          const st = eventStatus(e, this.currentTime)
          items.push({
            type: 'event', key: 'ev-' + e.uid, top, height: ITEM_HEIGHT,
            uid: e.uid, dateStr: g.date, summary: e.summary, description: e.description,
            dtstart: e.dtstart, dtend: e.dtend,
            range: fmtTime(e.dtstart) + ' - ' + fmtTime(e.dtend),
            status: st,
          })
          top += ITEM_HEIGHT
        }
      }
      return items
    },
    totalHeight() { return this.virtualItems.length ? this.virtualItems[this.virtualItems.length - 1].top + this.virtualItems[this.virtualItems.length - 1].height : 0 },
    visibleItems() {
      const start = Math.max(0, this.scrollTop - OVERSCAN * ITEM_HEIGHT)
      const end = this.scrollTop + this.containerHeight + OVERSCAN * ITEM_HEIGHT
      return this.virtualItems.filter(i => i.top + i.height >= start && i.top <= end)
    },
    floatingDateItem() {
      if (!this.virtualItems.length) return null
      let current = null
      for (const item of this.virtualItems) {
        if (item.type === 'header') current = item
        if (item.top > this.scrollTop) break
      }
      return current || this.virtualItems.find(i => i.type === 'header')
    },
    stickyHeader() {
      if (!this.virtualItems.length) return null
      let current = null
      const scrollTop = this.scrollTop
      for (const item of this.virtualItems) {
        if (item.type === 'header') current = item
        if (item.top + item.height > scrollTop) break
      }
      return current
    },
    currentYearMonth() {
      const d = this.floatingDateItem ? icalDateToObj(this.floatingDateItem.dateStr + 'T00:00:00') : this.currentTime
      return d ? `${d.getFullYear()}年${d.getMonth() + 1}月` : ''
    },
    currentWeek() {
      const d = this.floatingDateItem ? icalDateToObj(this.floatingDateItem.dateStr + 'T00:00:00') : this.currentTime
      return d ? weekNumber(d) : ''
    },
    selectedEvent() {
      if (this.selectedUids.length !== 1) return null
      return this.eventsMap[this.selectedUids[0]]
    },
  },
  mounted() {
    this.currentTime = new Date()
    this._nowTimer = setInterval(() => { this.currentTime = new Date() }, 30000)
    this.$nextTick(() => {
      if (this.$refs.listRef) {
        this.containerHeight = this.$refs.listRef.clientHeight
        this.loadInitial()
      }
    })
    window.addEventListener('resize', this.onResize)
    document.addEventListener('click', () => { this.ctxMenu.show = false })
    this._mounted = true
  },
  beforeUnmount() {
    window.removeEventListener('resize', this.onResize)
    clearInterval(this._nowTimer)
  },
  methods: {
    fmtTime,
    fmtFullDate(s) {
      const d = icalDateToObj(s)
      return d ? `${d.getFullYear()}年${d.getMonth()+1}月${d.getDate()}日` : ''
    },
    async loadInitial() {
      this.loading = true
      this._loadingInitial = true
      const now = this.currentTime
      const start = new Date(now.getFullYear(), now.getMonth() - 1, 1)
      const end = new Date(now.getFullYear(), now.getMonth() + 2, 0)
      this._loadStart = fmtDate(start)
      this._loadEnd = fmtDate(end)
      try {
        const res = await api.listEvents(0, 500, this._loadStart, this._loadEnd)
        this.events = Array.isArray(res) ? res : (res.items || [])
      } catch (e) {}
      this._loadingInitial = false
      this.loading = false
      setTimeout(() => this.scrollToToday(), 150)
    },
    async loadMore(dir) {
      if (this.loading || this._loadingInitial) return
      this.loading = true
      let from, to
      if (dir === 'prev') {
        const s = new Date(this._loadStart); s.setMonth(s.getMonth() - 2)
        from = fmtDate(s); to = this._loadStart
      } else {
        const e = new Date(this._loadEnd); e.setMonth(e.getMonth() + 2)
        from = this._loadEnd; to = fmtDate(e)
      }
      try {
        const res = await api.listEvents(0, 500, from, to)
        const items = Array.isArray(res) ? res : (res.items || [])
        const existing = new Map(this.events.map(e => [e.uid, e]))
        items.forEach(e => existing.set(e.uid, e))
        this.events = [...existing.values()]
        if (dir === 'prev') this._loadStart = from; else this._loadEnd = to
      } catch (e) {}
      this.loading = false
    },
    scrollToToday() {
      const todayStr = fmtDate(this.currentTime)
      const now = this.currentTime
      const items = this.virtualItems
      const header = items.find(i => i.type === 'header' && i.dateStr === todayStr)
      if (!header || !this.$refs.listRef) return
      let scrollPos = header.top
      const todayEvents = items.filter(i => i.type === 'event' && i.dateStr === todayStr && i.status !== 'ended')
      const ongoing = todayEvents.find(i => i.status === 'ongoing')
      if (ongoing) {
        scrollPos = ongoing.top + ongoing.height / 2 - this.containerHeight / 2
      } else if (todayEvents.length > 0) {
        const first = todayEvents[0]
        const last = todayEvents[todayEvents.length - 1]
        const mid = (first.top + last.top + last.height) / 2
        scrollPos = mid - this.containerHeight / 2
      } else {
        const hours = now.getHours() + now.getMinutes() / 60
        const ratio = hours / 24
        scrollPos = header.top + 60 + ratio * (EMPTY_HEIGHT + 20)
      }
      this.$refs.listRef.scrollTop = Math.max(0, scrollPos)
    },
    onScroll() {
      if (!this.$refs.listRef || !this._mounted) return
      this.scrollTop = this.$refs.listRef.scrollTop
      const threshold = 500
      if (this.scrollTop < threshold) this.loadMore('prev')
      else if (this.scrollTop + this.containerHeight > this.totalHeight - threshold) this.loadMore('next')
    },
    onResize() { if (this.$refs.listRef) this.containerHeight = this.$refs.listRef.clientHeight },
    isSelected(item) { return item.type === 'event' && this.selectedUids.includes(item.uid) },
    onItemClick(item, ev) {
      if (item.type !== 'event') return
      if (ev.ctrlKey || ev.metaKey) {
        const idx = this.selectedUids.indexOf(item.uid)
        if (idx >= 0) this.selectedUids.splice(idx, 1); else this.selectedUids.push(item.uid)
      } else if (ev.shiftKey && this.selectedUids.length) {
        const all = this.virtualItems.filter(i => i.type === 'event')
        const lastIdx = all.findIndex(i => i.uid === this.selectedUids[this.selectedUids.length - 1])
        const curIdx = all.findIndex(i => i.uid === item.uid)
        if (lastIdx >= 0 && curIdx >= 0) {
          const [s, e] = lastIdx < curIdx ? [lastIdx, curIdx] : [curIdx, lastIdx]
          this.selectedUids = [...new Set([...this.selectedUids, ...all.slice(s, e+1).map(i => i.uid)])]
        }
      } else {
        this.selectedUids = [item.uid]
      }
    },
    onCtxMenu(item, ev) {
      if (!this.selectedUids.includes(item.uid)) this.selectedUids = [item.uid]
      this.ctxMenu = { show: true, x: ev.clientX, y: ev.clientY, uids: [...this.selectedUids] }
    },
    cardSideStyle(item) {
      if (item.status === 'ended') return { background: '#e0e0e0' }
      if (item.status === 'upcoming') return { background: 'var(--theme,#1677ff)' }
      const st = icalDateToObj(item.dtstart), et = icalDateToObj(item.dtend)
      if (!st || !et) return { background: 'var(--theme,#1677ff)' }
      const pct = Math.min(Math.max((this.currentTime - st) / (et - st) * 100, 0), 100)
      return { background: `linear-gradient(to bottom, #e0e0e0 ${pct}%, var(--theme,#1677ff) ${pct}%)` }
    },
    startEdit(e) {
      this.editForm = {
        summary: e.summary || '',
        dtstart: icalToDatetimeLocal(e.dtstart),
        dtend: icalToDatetimeLocal(e.dtend),
        location: e.location || '',
        description: e.description || '',
        categories: e.categories || '',
      }
      this.editModal = { ...e, isNew: false }
    },
    async saveEdit() {
      if (!this.editForm.summary || !this.editForm.dtstart || !this.editForm.dtend) return alert('请填写完整信息')
      this.saving = true
      const ical = [
        'BEGIN:VEVENT',
        `UID:${this.editModal.isNew ? '' : this.editModal.uid}`,
        `SUMMARY:${this.editForm.summary}`,
        `DTSTART:${this.editForm.dtstart.replace(/[-:]/g, '')}00`,
        `DTEND:${this.editForm.dtend.replace(/[-:]/g, '')}00`,
        `LOCATION:${this.editForm.location}`,
        `DESCRIPTION:${this.editForm.description}`,
        `CATEGORIES:${this.editForm.categories}`,
        'END:VEVENT'
      ].join('\r\n')
      try {
        if (this.editModal.isNew) await api.createEvent(ical); else await api.updateEvent(this.editModal.uid, ical)
        this.editModal = null
        this.loadInitial()
      } catch (e) { alert('保存失败') }
      this.saving = false
    },
    async deleteSingle(e) {
      if (!confirm('确认删除此日程？')) return
      try { await api.deleteEvent(e.uid); this.events = this.events.filter(x => x.uid !== e.uid); this.selectedUids = [] } catch (e) { alert('删除失败') }
    },
    async deleteSelected() {
      if (!confirm(`确认删除选中的 ${this.selectedUids.length} 个日程？`)) return
      try {
        await Promise.all(this.selectedUids.map(uid => api.deleteEvent(uid)))
        this.events = this.events.filter(e => !this.selectedUids.includes(e.uid))
        this.selectedUids = []
      } catch (e) { alert('部分删除失败') }
    },
    _toICS(events) {
      const vevents = events.map(e => [
        'BEGIN:VEVENT',
        `UID:${e.uid || ''}`,
        `DTSTART:${(e.dtstart || '').replace(/[-:]/g, '')}`,
        `DTEND:${(e.dtend || '').replace(/[-:]/g, '')}`,
        `SUMMARY:${e.summary || ''}`,
        e.description ? `DESCRIPTION:${e.description}` : '',
        e.location ? `LOCATION:${e.location}` : '',
        e.categories ? `CATEGORIES:${e.categories}` : '',
        'END:VEVENT',
      ].filter(Boolean).join('\r\n')).join('\r\n')
      return `BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//PersonalDAV//CN\r\n${vevents}\r\nEND:VCALENDAR`
    },
    _downloadIcs(content, name) {
      const blob = new Blob([content], { type: 'text/calendar;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url; a.download = name
      a.click(); URL.revokeObjectURL(url)
    },
    exportSingle(e) {
      const content = this._toICS([e])
      this._downloadIcs(content, `${e.summary || '日程'}.ics`)
    },
    exportSelected() {
      const items = this.events.filter(e => this.selectedUids.includes(e.uid))
        .sort((a,b) => a.dtstart.localeCompare(b.dtstart))
      const content = this._toICS(items)
      this._downloadIcs(content, `日程_${Date.now()}.ics`)
      this.ctxMenu.show = false
    },
    createForFloatingDate() {
      const fd = this.floatingDateItem
      const dateStr = fd ? fd.dateStr : fmtDate(this.currentTime)
      const startH = this.currentTime.getHours()
      const endH = Math.min(startH + 1, 23)
      this.editForm = {
        summary: '', dtstart: `${dateStr}T${pad(startH)}:00`,
        dtend: `${dateStr}T${pad(endH)}:00`,
        location: '', description: '', categories: '',
      }
      this.editModal = { isNew: true }
    }
  }
}
</script>

<style scoped>
.agenda-container { display: flex; height: 100%; background: #f8f9fa; gap: 20px; padding: 20px; box-sizing: border-box; }

.agenda-list-side { flex: 1; min-width: 0; display: flex; flex-direction: column; background: #fff; border-radius: 16px; box-shadow: 0 4px 20px rgba(0,0,0,0.05); overflow: hidden; }
.agenda-header { padding: 20px 24px; border-bottom: 1px solid #f0f0f0; flex-shrink: 0; display: flex; align-items: center; justify-content: space-between; }
.ah-left { display: flex; flex-direction: column; }
.ah-title { font-size: 22px; font-weight: 700; color: #1a1a1a; }
.ah-week { font-size: 14px; color: #888; margin-top: 4px; }
.btn-create { padding: 8px 16px; background: var(--theme, #1677ff); color: #fff; border: none; border-radius: 8px; cursor: pointer; font-weight: 500; }

.scroll-viewport { flex: 1; overflow-y: auto; position: relative; scroll-behavior: smooth; }
.virtual-list { position: relative; width: 100%; }
.list-item { position: absolute; left: 0; right: 0; padding: 0 16px; box-sizing: border-box; }

.date-header { display: flex; justify-content: space-between; align-items: center; padding: 12px 8px; border-bottom: 1px solid #f5f5f5; background: #fff; }
.floating-date-header { position: sticky; top: 0; z-index: 20; display: flex; justify-content: space-between; align-items: center; padding: 10px 20px; border-bottom: 1px solid #e8e8e8; background: #fff; box-shadow: 0 2px 8px rgba(0,0,0,0.06); min-height: 44px; }
.fh-date { font-weight: 700; color: #333; font-size: 15px; }
.fh-weekday { margin-left: 8px; color: #999; font-size: 13px; }
.fh-right { font-size: 12px; color: #aaa; }
.dh-date { font-weight: 700; color: #333; font-size: 15px; }
.dh-weekday { margin-left: 8px; color: #999; font-size: 13px; }
.dh-right { font-size: 12px; color: #aaa; }

.event-card-wrapper { display: flex; background: #fff; border-radius: 12px; margin: 4px 0; height: 72px; cursor: pointer; border: 1px solid transparent; transition: all 0.2s; box-shadow: 0 2px 8px rgba(0,0,0,0.02); }
.event-card-wrapper:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.06); border-color: #eee; }
.is-selected .event-card-wrapper { background: #e6f4ff; border-color: #1677ff; }

.card-side-bar { width: 4px; border-radius: 4px 0 0 4px; flex-shrink: 0; }
.card-content { flex: 1; padding: 12px 16px; min-width: 0; display: flex; flex-direction: column; justify-content: center; }
.card-main { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; }
.card-title { font-weight: 600; font-size: 15px; color: #1a1a1a; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.card-title.is-ended { color: #999; }
.card-time { font-size: 13px; color: #666; flex-shrink: 0; }
.card-time.is-ended { color: #bbb; }
.card-desc { font-size: 12px; color: #888; margin-top: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.card-desc.is-ended { color: #ccc; }

.empty-day { padding: 10px 8px; color: #bbb; font-size: 13px; font-style: italic; }
.now-bar-wrapper { display: flex; align-items: center; padding: 0 24px; }
.now-bar-line { flex: 1; height: 2px; background: #ff4d4f; border-radius: 2px; box-shadow: 0 0 6px rgba(255,77,79,0.4); }

.agenda-detail-side { width: 380px; flex-shrink: 0; background: #fff; border-radius: 16px; box-shadow: 0 4px 20px rgba(0,0,0,0.05); padding: 32px; overflow-y: auto; }
.detail-header h2 { margin: 0; font-size: 24px; color: #1a1a1a; }
.detail-meta { margin-top: 12px; }
.meta-tag { display: inline-block; padding: 2px 10px; background: #f0f2f5; border-radius: 4px; font-size: 12px; color: #666; }
.detail-body { margin-top: 32px; display: flex; flex-direction: column; gap: 24px; }
.detail-row { display: flex; gap: 16px; }
.detail-row .icon { font-style: normal; font-size: 18px; color: #888; }
.row-val { font-size: 15px; color: #333; line-height: 1.5; }
.time-range { font-weight: 600; font-size: 17px; }
.date-val { color: #888; font-size: 14px; margin-top: 2px; }
.desc-text { white-space: pre-wrap; word-break: break-all; }
.detail-footer { margin-top: 48px; border-top: 1px solid #f0f0f0; padding-top: 24px; display: flex; flex-wrap: wrap; gap: 12px; }

.btn-action { padding: 10px 20px; border-radius: 8px; border: 1px solid #d9d9d9; background: #fff; cursor: pointer; font-size: 14px; transition: all 0.2s; }
.btn-action:hover { border-color: #1677ff; color: #1677ff; }
.btn-danger { border-color: #ff4d4f; color: #ff4d4f; }
.btn-danger:hover { border-color: #ff4d4f; color: #ff4d4f; }
.btn-close { border: none; background: transparent; cursor: pointer; font-size: 22px; color: #999; padding: 4px 8px; line-height: 1; }
.btn-close:hover { color: #333; }

.detail-empty { height: 100%; display: flex; flex-direction: column; align-items: center; justify-content: center; color: #aaa; text-align: center; }
.empty-icon { font-size: 48px; margin-bottom: 16px; opacity: 0.3; }

.modal-overlay { position: fixed; inset: 0; z-index: 1000; background: rgba(0,0,0,0.4); display: flex; align-items: center; justify-content: center; backdrop-filter: blur(4px); }
.modal-card { background: #fff; width: 500px; border-radius: 20px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); overflow: hidden; }
.modal-header { padding: 20px 24px; border-bottom: 1px solid #f0f0f0; display: flex; justify-content: space-between; align-items: center; }
.modal-body { padding: 24px; display: flex; flex-direction: column; gap: 16px; }
.form-group { display: flex; flex-direction: column; gap: 6px; }
.form-group label { font-size: 13px; font-weight: 600; color: #666; }
.form-group input, .form-group textarea { padding: 10px 12px; border: 1px solid #d9d9d9; border-radius: 8px; font-size: 14px; }
.form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.modal-footer { padding: 16px 24px; background: #fafafa; display: flex; justify-content: flex-end; gap: 12px; }
.btn-save { background: #1677ff; color: #fff; border: none; padding: 8px 24px; border-radius: 8px; cursor: pointer; }
.btn-cancel { background: transparent; border: 1px solid #d9d9d9; padding: 8px 24px; border-radius: 8px; cursor: pointer; }

.ctx-menu { position: fixed; z-index: 1100; background: #fff; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); padding: 4px; min-width: 140px; }
.ctx-item { padding: 8px 12px; font-size: 13px; cursor: pointer; border-radius: 4px; }
.ctx-item:hover { background: #f5f5f5; }
.ctx-item.danger { color: #ff4d4f; }

.list-loading { padding: 20px; text-align: center; color: #999; }
</style>
