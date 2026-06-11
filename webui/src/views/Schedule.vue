<template>
  <div class="schedule-layout">
    <div class="schedule-left">
      <div class="schedule-top">
        <div class="st-year-month">{{ currentYearMonth }}</div>
        <div class="st-week">第 {{ currentWeek }} 周</div>
      </div>
      <div class="schedule-scroll">
        <div class="floating-header" v-if="floatingDate">
          <div class="fh-left">
            <span class="fh-date">{{ floatingDate.label }}</span>
            <span class="fh-weekday">{{ floatingDate.weekday }}</span>
          </div>
          <div class="fh-right">
            <button class="btn-xs" @click="createForDate(floatingDate.dateStr)">+ 新建</button>
          </div>
        </div>
        <div class="schedule-list" ref="listRef" @scroll="onScroll">
          <div class="vl-total" :style="{ height: totalHeight + 'px' }">
            <div v-for="item in visibleItems" :key="item.key"
              class="vl-row"
              :class="{ 'vl-date-header': item.type === 'header', 'vl-event': item.type === 'event', 'vl-selected': item.type === 'event' && selectedUids.length === 1 && selectedUids[0] === item.uid }"
              :style="{ transform: 'translateY(' + item.top + 'px)' }"
              @click="item.type === 'event' && onEventClick(item, $event)"
              @contextmenu.prevent="item.type === 'event' && onCtxMenu(item, $event)">
              <template v-if="item.type === 'header'">
                <div class="dh-left">
                  <span class="dh-date">{{ item.label }}</span>
                  <span class="dh-weekday">{{ item.weekday }}</span>
                </div>
                <div class="dh-right" v-if="item.lunar">{{ item.lunar }}</div>
              </template>
              <template v-else>
                <div class="card-side" :style="cardSideStyle(item)"></div>
                <div class="card-body">
                  <div class="card-title" :class="{ 'card-ended': item.status === 'ended' }">{{ item.summary || '(无标题)' }}</div>
                  <div class="card-time" :class="{ 'card-ended': item.status === 'ended' }">{{ item.range }}</div>
                  <div v-if="item.description" class="card-desc" :class="{ 'card-ended': item.status === 'ended' }">{{ item.description }}</div>
                </div>
              </template>
            </div>
          </div>
          <div v-if="loading" class="vl-loading">加载中...</div>
        </div>
      </div>
    </div>
    <div class="schedule-right">
      <template v-if="selectedEvent">
        <h3>{{ selectedEvent.summary || '(无标题)' }}</h3>
        <div class="sd-row"><label>时间</label><span>{{ fmtTime(selectedEvent.dtstart) }} - {{ fmtTime(selectedEvent.dtend) }}</span></div>
        <div v-if="selectedEvent.description" class="sd-row"><label>描述</label><span>{{ selectedEvent.description }}</span></div>
        <div v-if="selectedEvent.location" class="sd-row"><label>地点</label><span>{{ selectedEvent.location }}</span></div>
        <div v-if="selectedEvent.categories" class="sd-row"><label>分类</label><span>{{ selectedEvent.categories }}</span></div>
        <div class="sd-actions">
          <button class="btn-sm" @click="exportSingle">分享/导出</button>
          <button class="btn-sm" @click="editModal = selectedEvent">编辑</button>
          <button class="btn-sm btn-danger" @click="deleteSingle">删除</button>
        </div>
      </template>
      <div class="sd-empty" v-else-if="selectedUids.length > 1">请选择单个日程查看详情</div>
      <div class="sd-empty" v-else>点击左侧日程查看详情</div>
    </div>
    <!-- Detail/Edit Modal -->
    <div v-if="detailEvent" class="modal-overlay" @click.self="detailEvent = null">
      <div class="modal-card">
        <div class="modal-header">
          <h3>{{ detailEvent.summary || '(无标题)' }}</h3>
          <button class="btn-plain close-btn" @click="detailEvent = null">&times;</button>
        </div>
        <div class="modal-body">
          <div class="modal-row"><label>时间</label><span>{{ fmtTime(detailEvent.dtstart) }} - {{ fmtTime(detailEvent.dtend) }}</span></div>
          <div v-if="detailEvent.description" class="modal-row"><label>描述</label><span>{{ detailEvent.description }}</span></div>
          <div v-if="detailEvent.location" class="modal-row"><label>地点</label><span>{{ detailEvent.location }}</span></div>
          <div v-if="detailEvent.categories" class="modal-row"><label>分类</label><span>{{ detailEvent.categories }}</span></div>
        </div>
        <div class="modal-actions">
          <button class="btn-sm" @click="exportSingle(detailEvent)">分享/导出</button>
          <button class="btn-sm" @click="editModal = detailEvent; detailEvent = null">编辑</button>
          <button class="btn-sm btn-danger" @click="deleteSingle(detailEvent)">删除</button>
        </div>
      </div>
    </div>
    <div v-if="editModal" class="modal-overlay" @click.self="editModal = null">
      <div class="modal-card modal-card-wide">
        <div class="modal-header">
          <h3>编辑日程</h3>
          <button class="btn-plain close-btn" @click="editModal = null">&times;</button>
        </div>
        <div class="modal-body">
          <div class="form-row"><label>标题</label><input v-model="editForm.summary" /></div>
          <div class="form-row"><label>开始</label><input v-model="editForm.dtstart" type="datetime-local" /></div>
          <div class="form-row"><label>结束</label><input v-model="editForm.dtend" type="datetime-local" /></div>
          <div class="form-row"><label>地点</label><input v-model="editForm.location" /></div>
          <div class="form-row"><label>描述</label><textarea v-model="editForm.description" rows="3"></textarea></div>
          <div class="form-row"><label>分类</label><input v-model="editForm.categories" /></div>
        </div>
        <div class="modal-actions">
          <button class="btn-sm btn-primary" @click="saveEdit">保存</button>
          <button class="btn-sm" @click="editModal = null">取消</button>
        </div>
      </div>
    </div>
    <!-- Context Menu -->
    <div v-if="ctxMenu.show" class="ctx-menu" :style="{ top: ctxMenu.y + 'px', left: ctxMenu.x + 'px' }" @click.stop>
      <div class="ctx-item" @click="exportCtx">分享/导出</div>
      <div class="ctx-item" @click="editCtx" :class="{ disabled: ctxMenu.uids.length !== 1 }">编辑</div>
      <div class="ctx-item danger" @click="deleteCtx">删除</div>
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
  if (s.includes('T')) return s.substring(0, 16)
  return s.substring(0, 10) + 'T00:00'
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

function fmtTimeRange(s, e) {
  return fmtTime(s) + ' - ' + fmtTime(e)
}

function eventStatus(e, now) {
  const st = icalDateToObj(e.dtstart)
  const et = icalDateToObj(e.dtend)
  if (!st || !et) return 'upcoming'
  if (now >= et) return 'ended'
  if (now >= st) return 'ongoing'
  return 'upcoming'
}

function weekNumber(d) {
  const s = new Date(d.getFullYear(), 0, 1)
  const diff = d - s + (s.getTimezoneOffset() - d.getTimezoneOffset()) * 60000
  return Math.ceil((diff / 86400000 + s.getDay() + 1) / 7)
}

const WEEKDAY_NAMES = ['日', '一', '二', '三', '四', '五', '六']
const HEADER_HEIGHT = 44
const ITEM_HEIGHT = 72
const OVERSCAN = 10

export default {
  data: () => ({
    events: [],
    loading: false,
    scrollTop: 0,
    containerHeight: 600,
    selectedUids: [],
    selectedEvent: null,
    detailEvent: null,
    editModal: null,
    editForm: { summary: '', dtstart: '', dtend: '', location: '', description: '', categories: '' },
    ctxMenu: { show: false, x: 0, y: 0, uids: [] },
    now: new Date(),
    _nowTimer: null,
    _loadStart: '2000-01-01',
    _loadEnd: '2099-12-31',
  }),
  mounted() {
    this.now = new Date()
    this._nowTimer = setInterval(() => { this.now = new Date() }, 30000)
    this.$nextTick(() => {
      if (this.$refs.listRef) {
        this.containerHeight = this.$refs.listRef.clientHeight
        this.loadRange()
      }
    })
    window.addEventListener('resize', this.onResize)
    document.addEventListener('click', this.onClickAway)
  },
  beforeUnmount() {
    window.removeEventListener('resize', this.onResize)
    document.removeEventListener('click', this.onClickAway)
    clearInterval(this._nowTimer)
  },
  computed: {
    grouped() {
      const groups = {}
      for (const e of this.events) {
        const d = fmtDate(e.dtstart)
        if (!groups[d]) groups[d] = { date: d, events: [], lunar: '' }
        groups[d].events.push(e)
      }
      const keys = Object.keys(groups).sort()
      const today = fmtDate(new Date())
      const result = []
      for (const k of keys) {
        const g = groups[k]
        g.events.sort((a, b) => (a.dtstart || '').localeCompare(b.dtstart || ''))
        if (k === today || g.events.length > 0) {
          result.push(g)
        }
      }
      if (!result.find(g => g.date === today) && keys.length) {
        const now = fmtDate(new Date())
        if (!result.find(g => g.date === now)) {
          result.push({ date: now, events: [], lunar: '' })
        }
        result.sort((a, b) => a.date.localeCompare(b.date))
      }
      if (!result.length) {
        result.push({ date: fmtDate(new Date()), events: [], lunar: '' })
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
      let top = 0
      for (const g of this.grouped) {
        const dt = icalDateToObj(g.date + 'T00:00:00')
        const wd = dt ? WEEKDAY_NAMES[dt.getDay()] : ''
        const label = `${parseInt(g.date.split('-')[1])}月${parseInt(g.date.split('-')[2])}日`
        items.push({ type: 'header', key: 'h-' + g.date, top, height: HEADER_HEIGHT, dateStr: g.date, label, weekday: '周' + wd, lunar: g.lunar })
        top += HEADER_HEIGHT
        if (!g.events.length) {
          items.push({ type: 'empty', key: 'e-' + g.date, top, height: ITEM_HEIGHT, dateStr: g.date })
          top += ITEM_HEIGHT
        }
        for (const e of g.events) {
          const st = eventStatus(e, this.now)
          const startLabel = fmtTime(e.dtstart)
          const endLabel = fmtTime(e.dtend)
          items.push({
            type: 'event', key: 'e-' + e.uid, top, height: ITEM_HEIGHT,
            uid: e.uid, dateStr: g.date, summary: e.summary, description: e.description,
            dtstart: e.dtstart, dtend: e.dtend,
            time: startLabel, range: startLabel + ' - ' + endLabel,
            status: st,
          })
          top += ITEM_HEIGHT
        }
      }
      return items
    },
    totalHeight() { return this.virtualItems.reduce((s, i) => s + i.height, 0) },
    visibleItems() {
      const start = Math.max(0, this.scrollTop - OVERSCAN * ITEM_HEIGHT)
      const end = this.scrollTop + this.containerHeight + OVERSCAN * ITEM_HEIGHT
      let items = this.virtualItems.filter(i => i.top + i.height >= start && i.top <= end)
      if (items.length && items[0].type === 'event') {
        const hTop = this.virtualItems.find(i => i.type === 'header' && i.dateStr === items[0].dateStr)
        if (hTop && !items.includes(hTop)) {
          items = [hTop, ...items]
        }
      }
      return items
    },
    floatingDate() {
      if (!this.virtualItems.length) return null
      let current = null
      for (const item of this.virtualItems) {
        if (item.type === 'header') current = item
        if (item.top + item.height > this.scrollTop) break
      }
      return current || this.virtualItems.find(i => i.type === 'header')
    },
    currentYearMonth() {
      const d = this.floatingDate ? icalDateToObj(this.floatingDate.dateStr + 'T00:00:00') : new Date()
      if (!d) return ''
      return `${d.getFullYear()}年${d.getMonth() + 1}月`
    },
    currentWeek() {
      const d = this.floatingDate ? icalDateToObj(this.floatingDate.dateStr + 'T00:00:00') : new Date()
      return d ? weekNumber(d) : ''
    },
  },
  methods: {
    fmtTime,
    async loadRange(dir) {
      if (this.loading) return
      this.loading = true
      const now = new Date()
      let fromStr, toStr
      if (dir === 'prev') {
        const s = new Date(this._loadStart)
        s.setMonth(s.getMonth() - 2)
        fromStr = `${s.getFullYear()}-${pad(s.getMonth() + 1)}-01`
        toStr = this._loadEnd
      } else if (dir === 'next') {
        fromStr = this._loadStart
        const e = new Date(this._loadEnd)
        e.setMonth(e.getMonth() + 2)
        toStr = `${e.getFullYear()}-${pad(e.getMonth() + 1)}-${pad(new Date(e.getFullYear(), e.getMonth() + 1, 0).getDate())}`
      } else {
        const start = new Date(now.getFullYear(), now.getMonth() - 1, 1)
        const end = new Date(now.getFullYear(), now.getMonth() + 2, 0)
        fromStr = `${start.getFullYear()}-${pad(start.getMonth() + 1)}-${pad(start.getDate())}`
        toStr = `${end.getFullYear()}-${pad(end.getMonth() + 1)}-${pad(end.getDate())}`
      }
      try {
        const res = await api.listEvents(0, 500, fromStr, toStr)
        const items = Array.isArray(res) ? res : (res.items || [])
        this.events = items
        this._loadStart = fromStr
        this._loadEnd = toStr
      } catch (e) { /* ignore */ }
      this.loading = false
      if (!dir) this.$nextTick(() => this.scrollToInitial())
    },
    extendRange(dir) {
      if (this.loading) return
      this.loadRange(dir)
    },
    scrollToInitial() {
      if (!this.$refs.listRef || !this.virtualItems.length) return
      const now = this.now
      const todayStr = fmtDate(now)
      let foundItem = null
      for (const item of this.virtualItems) {
        if (item.type !== 'event') continue
        const e = this.eventsMap[item.uid]
        if (!e) continue
        const st = icalDateToObj(e.dtstart)
        const et = icalDateToObj(e.dtend)
        if (st && et && now >= st && now <= et) {
          foundItem = item
          break
        }
      }
      if (foundItem) {
        this.$refs.listRef.scrollTop = Math.max(0, foundItem.top - this.containerHeight / 3)
        return
      }
      const todayGroup = this.grouped.find(g => g.date === todayStr)
      if (todayGroup && todayGroup.events.length) {
        const totalG = todayGroup.events.length * ITEM_HEIGHT + HEADER_HEIGHT
        const daySec = now.getHours() * 3600 + now.getMinutes() * 60 + now.getSeconds()
        const ratio = Math.min(daySec / 86400, 1)
        const headerTop = this.virtualItems.find(i => i.type === 'header' && i.dateStr === todayStr)
        if (headerTop) {
          this.$refs.listRef.scrollTop = Math.max(0, headerTop.top + HEADER_HEIGHT + totalG * ratio - this.containerHeight / 2)
          return
        }
      }
      const todayHeader = this.virtualItems.find(i => i.type === 'header' && i.dateStr === todayStr)
      if (todayHeader) {
        this.$refs.listRef.scrollTop = Math.max(0, todayHeader.top - 60)
      }
    },
    onScroll() {
      if (!this.$refs.listRef) return
      this.scrollTop = this.$refs.listRef.scrollTop
      this.checkLoadMore()
    },
    onResize() {
      if (this.$refs.listRef) this.containerHeight = this.$refs.listRef.clientHeight
    },
    checkLoadMore() {
      if (this.loading) return
      const threshold = 400
      if (this.scrollTop < threshold) {
        this.extendRange('prev')
      } else if (this.scrollTop + this.containerHeight > this.totalHeight - threshold) {
        this.extendRange('next')
      }
    },
    onClickAway() { this.ctxMenu.show = false },
    onEventClick(item, ev) {
      if (ev.ctrlKey || ev.metaKey) {
        const idx = this.selectedUids.indexOf(item.uid)
        if (idx >= 0) this.selectedUids.splice(idx, 1)
        else this.selectedUids.push(item.uid)
        this.selectedEvent = null
        return
      }
      if (ev.shiftKey && this.selectedUids.length) {
        const all = this.virtualItems.filter(i => i.type === 'event')
        const lastIdx = all.findIndex(i => i.uid === this.selectedUids[this.selectedUids.length - 1])
        const curIdx = all.findIndex(i => i.uid === item.uid)
        if (lastIdx >= 0 && curIdx >= 0) {
          const [start, end] = lastIdx < curIdx ? [lastIdx, curIdx] : [curIdx, lastIdx]
          const range = all.slice(start, end + 1).map(i => i.uid)
          const combined = new Set([...this.selectedUids, ...range])
          this.selectedUids = [...combined]
        }
        this.selectedEvent = null
        return
      }
      if (this.selectedUids.length === 1 && this.selectedUids[0] === item.uid) {
        this.detailEvent = this.eventsMap[item.uid] || null
        return
      }
      this.selectedUids = [item.uid]
      this.selectedEvent = this.eventsMap[item.uid] || null
    },
    onCtxMenu(item, ev) {
      if (!this.selectedUids.includes(item.uid)) {
        this.selectedUids = [item.uid]
        this.selectedEvent = this.eventsMap[item.uid] || null
      }
      this.ctxMenu = { show: true, x: ev.clientX, y: ev.clientY, uids: [...this.selectedUids] }
    },
    cardSideStyle(item) {
      if (item.status === 'ended') return { background: '#ccc' }
      if (item.status === 'upcoming') return { background: 'var(--theme,#1677ff)' }
      if (item.status === 'empty') return { background: 'transparent' }
      const e = this.eventsMap[item.uid]
      if (!e) return { background: 'var(--theme,#1677ff)' }
      const st = icalDateToObj(e.dtstart)
      const et = icalDateToObj(e.dtend)
      if (!st || !et) return { background: 'var(--theme,#1677ff)' }
      const total = et.getTime() - st.getTime()
      const elapsed = this.now.getTime() - st.getTime()
      const pct = total > 0 ? Math.min(elapsed / total * 100, 100) : 100
      return { background: `linear-gradient(to bottom, #ccc ${pct}%, var(--theme,#1677ff) ${pct}%)` }
    },
    createForDate(dateStr) {
      this.$router.push('/calendar/new?date=' + dateStr)
    },
    openDetail(e) {
      this.detailEvent = e
      this.ctxMenu.show = false
    },
    exportSingle(e) {
      const ev = e || this.selectedEvent
      if (!ev) return
      const text = fmtTimeRange(ev.dtstart, ev.dtend) + '  ' + (ev.summary || '')
      navigator.clipboard.writeText(text).then(() => {
        alert('已复制')
        this.detailEvent = null
      }).catch(() => {})
    },
    exportCtx() {
      const uids = this.ctxMenu.uids
      const items = this.events.filter(e => uids.includes(e.uid))
      const text = items.map(e => fmtTimeRange(e.dtstart, e.dtend) + '  ' + (e.summary || '')).join('\n')
      navigator.clipboard.writeText(text).then(() => { this.ctxMenu.show = false; alert('已复制') }).catch(() => {})
    },
    editCtx() {
      if (this.ctxMenu.uids.length !== 1) return
      const e = this.eventsMap[this.ctxMenu.uids[0]]
      if (!e) return
      this.editForm = {
        summary: e.summary || '',
        dtstart: icalToDatetimeLocal(e.dtstart),
        dtend: icalToDatetimeLocal(e.dtend),
        location: e.location || '',
        description: e.description || '',
        categories: e.categories || '',
      }
      this.editModal = e
      this.ctxMenu.show = false
    },
    async deleteCtx() {
      const count = this.ctxMenu.uids.length
      if (!confirm(`确认删除 ${count} 个日程？`)) return
      try {
        await Promise.all(this.ctxMenu.uids.map(uid => api.deleteEvent(uid)))
        this.ctxMenu.show = false
        this.events = this.events.filter(e => !this.ctxMenu.uids.includes(e.uid))
        this.selectedUids = this.selectedUids.filter(uid => !this.ctxMenu.uids.includes(uid))
        this.selectedEvent = null
      } catch (e) { alert('删除失败') }
    },
    async deleteSingle(e) {
      const ev = e || this.selectedEvent
      if (!ev || !confirm('确认删除此日程？')) return
      try {
        await api.deleteEvent(ev.uid)
        this.events = this.events.filter(x => x.uid !== ev.uid)
        this.selectedUids = this.selectedUids.filter(uid => uid !== ev.uid)
        this.selectedEvent = null
        this.detailEvent = null
      } catch (e) { alert('删除失败') }
    },
    async saveEdit() {
      if (!this.editModal) return
      const e = this.editModal
      const lines = []
      lines.push('BEGIN:VEVENT')
      lines.push('UID:' + e.uid)
      lines.push('DTSTART:' + this.editForm.dtstart.replace(/[^0-9T]/g, ''))
      lines.push('DTEND:' + this.editForm.dtend.replace(/[^0-9T]/g, ''))
      if (this.editForm.summary) lines.push('SUMMARY:' + this.editForm.summary)
      if (this.editForm.location) lines.push('LOCATION:' + this.editForm.location)
      if (this.editForm.description) lines.push('DESCRIPTION:' + this.editForm.description)
      if (this.editForm.categories) lines.push('CATEGORIES:' + this.editForm.categories)
      lines.push('END:VEVENT')
      try {
        await api.updateEvent(e.uid, lines.join('\r\n'))
        this.editModal = null
        this.loadRange()
      } catch (e) { alert('保存失败') }
    },
  },
}
</script>

<style scoped>
.schedule-layout { display: flex; gap: 0; height: 100%; }
.schedule-left { flex: 1; display: flex; flex-direction: column; min-width: 0; background: #fff; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,.06); overflow: hidden; }
.schedule-top { flex-shrink: 0; padding: 14px 16px 8px; border-bottom: 1px solid #f0f0f0; }
.st-year-month { font-size: 18px; font-weight: 700; color: #000; }
.st-week { font-size: 13px; color: #999; margin-top: 2px; }
.schedule-scroll { flex: 1; position: relative; overflow: hidden; }
.floating-header { position: absolute; top: 0; left: 0; right: 0; height: 40px; z-index: 10; background: #fff; display: flex; align-items: center; justify-content: space-between; padding: 0 16px; border-bottom: 1px solid #f0f0f0; }
.fh-left { display: flex; align-items: center; gap: 6px; }
.fh-date { font-size: 14px; font-weight: 600; color: #333; }
.fh-weekday { font-size: 12px; color: #999; }
.btn-xs { padding: 3px 10px; border: 1px solid #d9d9d9; background: #fff; border-radius: 4px; font-size: 12px; cursor: pointer; }
.schedule-list { height: 100%; overflow-y: auto; padding-top: 40px; }
.vl-total { position: relative; }
.vl-row { position: absolute; left: 0; right: 0; will-change: transform; }
.vl-date-header { display: flex; align-items: center; justify-content: space-between; padding: 6px 16px; background: #fafafa; border-bottom: 1px solid #f0f0f0; }
.dh-left { display: flex; gap: 6px; align-items: baseline; }
.dh-date { font-size: 14px; font-weight: 600; color: #333; }
.dh-weekday { font-size: 12px; color: #999; }
.dh-right { font-size: 12px; color: #999; }
.vl-event { display: flex; gap: 10px; padding: 0; cursor: pointer; border-bottom: 1px solid #f5f5f5; transition: background .1s; border-radius: 0; }
.vl-event:hover { background: #fafafa; }
.vl-event.vl-selected { background: #e6f4ff; }
.card-side { width: 4px; flex-shrink: 0; align-self: stretch; }
.card-body { flex: 1; min-width: 0; padding: 10px 14px 10px 0; }
.card-title { font-size: 14px; font-weight: 600; color: #000; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.card-title.card-ended { color: #999; }
.card-time { font-size: 12px; color: #555; margin-top: 2px; }
.card-time.card-ended { color: #bbb; }
.card-desc { font-size: 12px; color: #888; margin-top: 3px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.card-desc.card-ended { color: #ccc; }
.vl-loading { padding: 16px; text-align: center; color: #999; font-size: 13px; }
.schedule-right { width: 340px; flex-shrink: 0; background: #fff; border-radius: 8px; padding: 20px; margin-left: 16px; box-shadow: 0 1px 4px rgba(0,0,0,.06); overflow-y: auto; }
.schedule-right h3 { margin: 0 0 16px; font-size: 16px; }
.sd-row { display: flex; gap: 8px; margin-bottom: 10px; font-size: 14px; }
.sd-row label { color: #888; min-width: 48px; flex-shrink: 0; }
.sd-empty { display: flex; align-items: center; justify-content: center; height: 100%; color: #999; font-size: 14px; }
.sd-actions { display: flex; gap: 8px; margin-top: 20px; padding-top: 16px; border-top: 1px solid #f0f0f0; flex-wrap: wrap; }
.sd-actions .btn-sm { padding: 6px 16px; border-radius: 6px; font-size: 13px; text-decoration: none; border: 1px solid #d9d9d9; background: #fff; cursor: pointer; }
.btn-primary { background: #1677ff; color: #fff; border-color: #1677ff; }
.btn-danger { color: #cf1322; border-color: #ffa39e; }
.ctx-menu { position: fixed; z-index: 1000; background: #fff; border: 1px solid #e8e8e8; border-radius: 6px; box-shadow: 0 4px 12px rgba(0,0,0,.12); min-width: 120px; padding: 4px 0; }
.ctx-item { padding: 8px 16px; font-size: 13px; cursor: pointer; }
.ctx-item:hover { background: #f5f5f5; }
.ctx-item.disabled { color: #ccc; cursor: default; }
.ctx-item.danger { color: #cf1322; }
.ctx-item.danger:hover { background: #fff2f0; }
.modal-overlay { position: fixed; inset: 0; z-index: 999; background: rgba(0,0,0,.4); display: flex; align-items: center; justify-content: center; }
.modal-card { background: #fff; border-radius: 12px; min-width: 360px; max-width: 480px; box-shadow: 0 8px 24px rgba(0,0,0,.15); overflow: hidden; }
.modal-card-wide { min-width: 420px; }
.modal-header { display: flex; justify-content: space-between; align-items: center; padding: 16px 20px; border-bottom: 1px solid #f0f0f0; }
.modal-header h3 { margin: 0; font-size: 16px; }
.close-btn { font-size: 20px; line-height: 1; padding: 4px 8px; border: none; background: none; cursor: pointer; }
.modal-body { padding: 16px 20px; }
.modal-row { display: flex; gap: 8px; margin-bottom: 8px; font-size: 14px; }
.modal-row label { color: #888; min-width: 48px; flex-shrink: 0; }
.modal-actions { display: flex; gap: 8px; padding: 12px 20px; border-top: 1px solid #f0f0f0; }
.modal-actions .btn-sm { padding: 6px 16px; border-radius: 6px; font-size: 13px; text-decoration: none; border: 1px solid #d9d9d9; background: #fff; cursor: pointer; }
.form-row { display: flex; gap: 8px; margin-bottom: 10px; align-items: center; }
.form-row label { color: #888; min-width: 48px; flex-shrink: 0; font-size: 14px; }
.form-row input, .form-row textarea { flex: 1; padding: 6px 10px; border: 1px solid #d9d9d9; border-radius: 4px; font-size: 13px; }
.form-row textarea { resize: vertical; }
</style>
