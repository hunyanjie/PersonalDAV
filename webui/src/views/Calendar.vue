<template>
  <div class="calendar-page">
    <div class="toolbar glass">
      <div class="nav-controls">
        <button class="btn-icon" @click="monthOffset-=12" title="上一年"><ChevronsLeft :size="18" /></button>
        <button class="btn-nav" @click="monthOffset--"><ChevronLeft :size="18" /> 上月</button>
        <span class="month-label">{{ year }} 年 {{ month }} 月</span>
        <button class="btn-nav" @click="monthOffset++">下月 <ChevronRight :size="18" /></button>
        <button class="btn-icon" @click="monthOffset+=12" title="下一年"><ChevronsRight :size="18" /></button>
      </div>
      
      <div class="toolbar-right">
        <input v-model="jumpDate" type="date" class="date-input" @change="jumpToDate" />
        <div class="search-box">
          <Search :size="16" class="search-icon" />
          <input v-model="searchQuery" class="search-input" placeholder="搜索日程..." @input="doSearch" />
        </div>
        <label class="btn-tool btn-import">
          <Download :size="18" /> 导入
          <input type="file" accept=".ics" @change="doImportICS" hidden />
        </label>
        <router-link to="/calendar/new" class="btn-tool btn-primary">
          <Plus :size="18" /> 新建
        </router-link>
      </div>
    </div>

    <div v-if="errorMsg" class="error-banner">
      <AlertCircle :size="16" /> {{ errorMsg }}
    </div>

    <div class="calendar-grid-wrapper glass" v-if="!searchQuery">
      <table class="cal-table">
        <thead>
          <tr><th v-for="d in ['一','二','三','四','五','六','日']" :key="d">{{ d }}</th></tr>
        </thead>
        <tbody>
          <tr v-for="(week, wi) in weeks" :key="wi">
            <td v-for="(day, di) in week" :key="di"
              :class="cellClass(day)"
              @click="day.current && selectDay(day)">
              <div class="day-cell-content">
                <div class="day-num">{{ day.day }}</div>
                <div class="event-dots">
                  <span v-for="e in day.events.slice(0, 4)" :key="e.uid" class="dot" :class="{ 'dot-past': isEventPast(e) }" :title="e.summary || e.uid" />
                  <span v-if="day.events.length > 4" class="dot-more">+{{ day.events.length - 4 }}</span>
                </div>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Day Panel (Schedule style) -->
    <div v-if="selectedDay && !searchQuery" class="day-panel glass">
      <div class="panel-header">
        <div class="panel-title">
          <CalendarDays :size="20" class="title-icon" />
          <span class="panel-date">{{ selectedDay.year }}年{{ pad(selectedDay.month) }}月{{ pad(selectedDay.day) }}日</span>
        </div>
        <button class="btn-sm" @click="exportDay"><Share2 :size="14" /> 导出今日</button>
      </div>

      <!-- Timeline -->
      <div class="timeline-container">
        <div class="timeline" ref="timeline">
          <div class="tl-hours">
            <div v-for="h in 24" :key="h" class="tl-hour-label">{{ h }}</div>
          </div>
          <div class="tl-now-bar" :style="{ left: nowLeft }" v-if="isTodaySelected"></div>
          <div v-for="e in dayEvents" :key="e.uid"
            class="tl-dot"
            :class="{ 'tl-dot-past': isEventPast(e) }"
            :style="{ left: eventLeft(e) }"
            :title="e.summary"
            @click.stop="openDetail(e)" />
        </div>
      </div>

      <!-- Event Cards -->
      <div class="event-cards">
        <div v-for="e in dayEvents" :key="e.uid"
          class="event-card"
          :class="eventCardClass(e)"
          :data-uid="e.uid"
          @click="onCardClick(e, $event)"
          @contextmenu.prevent="onContextMenu(e, $event)">
          <div class="card-side" :style="cardSideStyle(e)" />
          <div class="card-body">
            <div class="card-main">
              <div class="card-title">{{ e.summary || '(无标题)' }}</div>
              <div class="card-time"><Clock :size="12" /> {{ formatTime(e.dtstart) }} - {{ formatTime(e.dtend) }}</div>
            </div>
            <div v-if="e.description" class="card-desc">{{ e.description }}</div>
          </div>
        </div>
        <div v-if="!dayEvents.length" class="empty-day-hint">当日无日程，点击「新建」添加</div>
      </div>
    </div>

    <!-- Search Results View -->
    <div v-if="searchQuery" class="search-results-panel glass">
      <div v-for="e in events" :key="e.uid" class="event-card" @click="openDetail(e)">
          <div class="card-side" :style="cardSideStyle(e)" />
          <div class="card-body">
            <div class="card-main">
              <div class="card-title">{{ e.summary || '(无标题)' }}</div>
              <div class="card-time"><Clock :size="12" /> {{ formatTime(e.dtstart) }} - {{ formatTime(e.dtend) }}</div>
            </div>
            <div class="card-date">{{ formatDateFull(e.dtstart) }}</div>
          </div>
      </div>
      <div v-if="!events.length" class="empty-hint">未找到匹配的日程</div>
    </div>

    <!-- Context Menu -->
    <div v-if="ctxMenu.show" class="ctx-menu glass" :style="{ top: ctxMenu.y + 'px', left: ctxMenu.x + 'px' }" @click.stop>
      <div class="ctx-item" @click="exportSelected"><Share2 :size="14" /> 分享/导出</div>
      <div class="ctx-item" @click="editSelected" :class="{ disabled: ctxMenu.uids.length !== 1 }"><Pencil :size="14" /> 编辑</div>
      <div class="ctx-divider"></div>
      <div class="ctx-item danger" @click="deleteSelected"><Trash2 :size="14" /> 删除</div>
    </div>

    <!-- Detail Modal -->
    <div v-if="detailEvent" class="modal-overlay" @click.self="detailEvent = null">
      <div class="modal-card glass">
        <div class="modal-header">
          <h3>{{ detailEvent.summary || '(无标题)' }}</h3>
          <button class="btn-close-circle" @click="detailEvent = null"><X :size="20" /></button>
        </div>
        <div class="modal-body">
          <div class="modal-row">
            <Clock :size="18" class="row-icon" />
            <div class="row-content">
              <div class="row-val">{{ formatTime(detailEvent.dtstart) }} - {{ formatTime(detailEvent.dtend) }}</div>
              <div class="row-label">{{ formatDateFull(detailEvent.dtstart) }}</div>
            </div>
          </div>
          <div v-if="detailEvent.location" class="modal-row">
            <MapPin :size="18" class="row-icon" />
            <div class="row-content">
              <div class="row-val">{{ detailEvent.location }}</div>
            </div>
          </div>
          <div v-if="detailEvent.categories" class="modal-row">
            <Layers :size="18" class="row-icon" />
            <div class="row-content">
              <div class="row-val">{{ detailEvent.categories }}</div>
            </div>
          </div>
          <div v-if="detailEvent.description" class="modal-row">
            <FileText :size="18" class="row-icon" />
            <div class="row-content">
              <div class="row-val desc-text">{{ detailEvent.description }}</div>
            </div>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn-action" @click="exportSingle(detailEvent)"><Share2 :size="14" /> 导出</button>
          <router-link :to="`/calendar/${detailEvent.uid}/edit`" class="btn-action"><Pencil :size="14" /> 编辑</router-link>
          <button class="btn-action btn-danger" @click="deleteSingle(detailEvent)"><Trash2 :size="14" /> 删除</button>
        </div>
      </div>
    </div>

    <div v-if="!events.length && !errorMsg && !selectedDay && !searchQuery" class="empty-hint">
      <CalendarIcon :size="48" class="empty-icon" />
      <p>当前月份无日程</p>
    </div>
  </div>
</template>

<script>
import { 
  ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, Search, 
  Download, Plus, AlertCircle, CalendarDays, Share2, Clock, 
  MapPin, Layers, FileText, X, Calendar as CalendarIcon, ChevronUp, ChevronDown
} from 'lucide-vue-next'
import api from '../api.js'

function pad(n) { return String(n).padStart(2, '0') }

function icalDateToObj(s) {
  if (!s) return null
  const m = s.match(/^(\d{4})-?(\d{2})-?(\d{2})[T ]?(\d{2}):?(\d{2})?(:\d{2})?/)
  if (!m) return null
  return new Date(+m[1], +m[2] - 1, +m[3], +m[4] || 0, +(m[5] || 0), 0)
}

function icalDateToStr(s) {
  if (!s) return ''
  const m = s.match(/^(\d{4})-?(\d{2})-?(\d{2})/)
  return m ? `${m[1]}-${m[2]}-${m[3]}` : s.substring(0, 10)
}

function eventSpansDate(e, dateStr) {
  const start = icalDateToStr(e.dtstart)
  if (!start) return false
  const end = icalDateToStr(e.dtend) || start
  return dateStr >= start && dateStr <= end
}

function toHours(d) {
  if (!d) return 0
  return d.getHours() + d.getMinutes() / 60
}

function eventStatus(e, now) {
  const st = icalDateToObj(e.dtstart)
  const et = icalDateToObj(e.dtend)
  if (!st || !et) return 'upcoming'
  if (now > et) return 'ended'
  if (now >= st && now <= et) return 'ongoing'
  return 'upcoming'
}

export default {
  components: { 
    ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, Search, 
    Download, Plus, AlertCircle, CalendarDays, Share2, Clock, 
    MapPin, Layers, FileText, X, CalendarIcon, ChevronUp, ChevronDown
  },
  data: () => ({
    events: [],
    monthOffset: 0,
    selectedDay: null,
    searchQuery: '',
    jumpDate: '',
    _searchTimer: null,
    errorMsg: '',
    detailEvent: null,
    selectedUids: [],
    ctxMenu: { show: false, x: 0, y: 0, uids: [] },
    currentTime: new Date(),
    _nowTimer: null,
  }),
  mounted() {
    this.load()
    this._nowTimer = setInterval(() => { this.currentTime = new Date() }, 10000)
    document.addEventListener('click', this.onClickAway)
  },
  beforeUnmount() { clearInterval(this._nowTimer); document.removeEventListener('click', this.onClickAway) },
  watch: {
    monthOffset() { this.selectedDay = null; this.load() },
  },
  computed: {
    now() { return this.currentTime },
    todayStr() {
      const d = this.currentTime
      return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
    },
    todayDate() {
      return { year: this.currentTime.getFullYear(), month: this.currentTime.getMonth() + 1, day: this.currentTime.getDate() }
    },
    calNow() { const d = this.currentTime; return new Date(d.getFullYear(), d.getMonth() + this.monthOffset, 1) },
    year() { return this.calNow.getFullYear() },
    month() { return this.calNow.getMonth() + 1 },
    isTodaySelected() {
      return this.selectedDay && this.selectedDay.year === this.todayDate.year
        && this.selectedDay.month === this.todayDate.month
        && this.selectedDay.day === this.todayDate.day
    },
    weeks() {
      const y = this.calNow.getFullYear(), m = this.calNow.getMonth()
      const first = new Date(y, m, 1).getDay() || 7
      const daysInMonth = new Date(y, m + 1, 0).getDate()
      const daysInPrev = new Date(y, m, 0).getDate()
      const weeks = []; let row = []
      const prev = daysInPrev - first + 2
      const today = this.todayStr
      for (let i = prev; i <= daysInPrev; i++) row.push({ day: i, current: false, hasEvent: false, events: [], isToday: false, isPast: false })
      for (let d = 1; d <= daysInMonth; d++) {
        const dateStr = `${y}-${pad(m + 1)}-${pad(d)}`
        const dayEvents = this.events.filter(e => eventSpansDate(e, dateStr))
        const isPast = dateStr < today
        const isToday = dateStr === today
        row.push({ day: d, current: true, hasEvent: dayEvents.length > 0, events: dayEvents, isToday, isPast })
        if (row.length === 7) { weeks.push(row); row = [] }
      }
      if (row.length) {
        for (let d = 1; row.length < 7; d++) row.push({ day: d, current: false, hasEvent: false, events: [], isToday: false, isPast: false })
        weeks.push(row)
      }
      return weeks
    },
    dayEvents() {
      if (!this.selectedDay) return []
      const { year, month, day } = this.selectedDay
      const dateStr = `${year}-${pad(month)}-${pad(day)}`
      return this.events
        .filter(e => eventSpansDate(e, dateStr))
        .sort((a, b) => (a.dtstart || '').localeCompare(b.dtstart || ''))
    },
    nowLeft() {
      const h = toHours(this.currentTime)
      return Math.min(((h / 24) * 100), 100) + '%'
    },
  },
  methods: {
    pad,
    monthRange() {
      const y = this.calNow.getFullYear(), m = this.calNow.getMonth() + 1
      const from = `${y}-${pad(m)}-01`
      const to = m === 12 ? `${y + 1}-01-01` : `${y}-${pad(m + 1)}-01`
      return { from, to }
    },
    async load() {
      this.errorMsg = ''
      this.selectedUids = []
      if (this.searchQuery) return
      const { from, to } = this.monthRange()
      try {
        const res = await api.listEvents(0, 500, from, to)
        this.events = Array.isArray(res) ? res : (res.items || [])
      } catch (e) {
        this.events = []
        this.errorMsg = '加载日程失败: ' + (e.message || e)
      }
      this.selectToday()
    },
    isEventPast(e) {
      const et = icalDateToObj(e.dtend)
      return et && et < this.currentTime
    },
    selectToday() {
      if (this.selectedDay) return
      const today = this.todayDate
      if (this.year === today.year && this.month === today.month) {
        this.selectedDay = { year: today.year, month: today.month, day: today.day }
      }
    },
    selectDay(day) {
      this.selectedDay = { year: this.year, month: this.month, day: day.day }
      this.selectedUids = []
      this.ctxMenu.show = false
    },
    cellClass(day) {
      return {
        'other-month': !day.current,
        'has-event': day.hasEvent,
        'today': day.isToday,
        'selected': this.isSelected(day),
        'past-day': day.isPast,
      }
    },
    isSelected(day) {
      return !!this.selectedDay && day.current
        && this.selectedDay.year === this.year
        && this.selectedDay.month === this.month
        && this.selectedDay.day === day.day
    },
    doSearch() {
      clearTimeout(this._searchTimer)
      this._searchTimer = setTimeout(() => {
        if (this.searchQuery.trim()) {
          api.searchEvents(this.searchQuery, '', '', 0, 500).then(results => {
            this.events = Array.isArray(results) ? results : (results.items || [])
            this.selectedDay = null
            this.errorMsg = ''
          }).catch(() => { this.errorMsg = '搜索失败' })
        } else {
          this.load()
        }
      }, 300)
    },
    jumpToDate() {
      if (!this.jumpDate) return
      const d = new Date(this.jumpDate)
      if (isNaN(d.getTime())) return
      this.monthOffset = (d.getFullYear() - new Date().getFullYear()) * 12 + (d.getMonth() - new Date().getMonth())
    },
    eventLeft(e) {
      const st = icalDateToObj(e.dtstart)
      if (!st) return '0%'
      const h = toHours(st)
      return ((h / 24) * 100) + '%'
    },
    eventCardClass(e) {
      const st = eventStatus(e, this.currentTime)
      const endStr = icalDateToStr(e.dtend) || icalDateToStr(e.dtstart)
      const isPastDay = !this.isTodaySelected && endStr < this.todayStr
      return {
        'card-ended': (st === 'ended' && this.isTodaySelected) || isPastDay,
        'card-ongoing': st === 'ongoing' && this.isTodaySelected,
        'card-upcoming': st === 'upcoming' || (!this.isTodaySelected && !isPastDay),
        'card-selected': this.selectedUids.includes(e.uid),
      }
    },
    cardSideStyle(e) {
      const st = eventStatus(e, this.currentTime)
      const endStr = icalDateToStr(e.dtend) || icalDateToStr(e.dtstart)
      const isPastDay = endStr < this.todayStr
      if (st === 'ended' || isPastDay) return { background: '#d9d9d9' }
      if (st === 'upcoming') return { background: 'var(--brand)' }
      
      const stDate = icalDateToObj(e.dtstart)
      const etDate = icalDateToObj(e.dtend)
      if (!stDate || !etDate) return { background: 'var(--brand)' }
      const total = etDate.getTime() - stDate.getTime()
      const elapsed = this.currentTime.getTime() - stDate.getTime()
      const pct = total > 0 ? Math.min(elapsed / total * 100, 100) : 100
      return { background: `linear-gradient(to bottom, #d9d9d9 ${pct}%, var(--brand) ${pct}%)` }
    },
    formatTime(s) {
      const d = icalDateToObj(s)
      if (!d) return s || ''
      return d.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' })
    },
    formatDateFull(s) {
      const d = icalDateToObj(s)
      return d ? d.toLocaleDateString('zh-CN', { year: 'numeric', month: 'long', day: 'numeric', weekday: 'long' }) : ''
    },
    onCardClick(e, ev) {
      if (ev.ctrlKey || ev.metaKey) {
        const idx = this.selectedUids.indexOf(e.uid)
        if (idx >= 0) this.selectedUids.splice(idx, 1)
        else this.selectedUids.push(e.uid)
        return
      }
      this.selectedUids = [e.uid]
      this.openDetail(e)
    },
    onContextMenu(e, ev) {
      if (!this.selectedUids.includes(e.uid)) {
        this.selectedUids = [e.uid]
      }
      this.ctxMenu = { show: true, x: ev.clientX, y: ev.clientY, uids: [...this.selectedUids] }
    },
    onClickAway() { this.ctxMenu.show = false },
    openDetail(e) { this.detailEvent = e; this.ctxMenu.show = false },
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
    exportDay() {
      const content = this._toICS(this.dayEvents)
      this._downloadIcs(content, `日程_${this.todayStr}.ics`)
    },
    exportSingle(e) {
      const content = this._toICS([e])
      this._downloadIcs(content, `${e.summary || '日程'}.ics`)
      this.detailEvent = null
    },
    exportSelected() {
      const items = this.dayEvents.filter(x => this.ctxMenu.uids.includes(x.uid))
      const content = this._toICS(items)
      this._downloadIcs(content, `日程_${Date.now()}.ics`)
      this.ctxMenu.show = false
    },
    editSelected() {
      if (this.ctxMenu.uids.length !== 1) return
      this.$router.push(`/calendar/${this.ctxMenu.uids[0]}/edit`)
    },
    deleteSelected() {
      const count = this.ctxMenu.uids.length
      if (!confirm(`确认删除 ${count} 个日程？`)) return
      Promise.all(this.ctxMenu.uids.map(uid => api.deleteEvent(uid))).then(() => {
        this.ctxMenu.show = false; this.load()
      }).catch(() => { this.errorMsg = '删除失败' })
    },
    deleteSingle(e) {
      if (!confirm('确认删除此日程？')) return
      api.deleteEvent(e.uid).then(() => {
        this.detailEvent = null; this.load()
      }).catch(() => { this.errorMsg = '删除失败' })
    },
    async doImportICS(e) {
      const file = e.target.files[0]
      if (!file) return
      try {
        const text = await file.text()
        const blocks = text.split(/(?=BEGIN:VEVENT)/).filter(Boolean)
        let ok = 0, fail = 0
        for (const block of blocks) {
          const ical = `BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//PersonalDAV//CN\r\n${block.trim()}\r\nEND:VCALENDAR`
          try { await api.createEvent(ical); ok++ }
          catch { fail++ }
        }
        alert(`导入完成：成功 ${ok} 条${fail ? `，失败 ${fail} 条` : ''}`)
        this.load()
      } catch(e) { alert('导入失败: ' + (e.message || e)) }
      e.target.value = ''
    },
  },
}
</script>

<style scoped>
.calendar-page { display: flex; flex-direction: column; gap: 16px; height: 100%; }

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
  flex-wrap: wrap;
}

.nav-controls { display: flex; align-items: center; gap: 8px; }
.btn-nav { 
  padding: 8px 16px; 
  border: 1px solid var(--border-strong); 
  background: white; 
  border-radius: var(--radius-sm); 
  cursor: pointer; 
  font-size: 14px; 
  display: flex;
  align-items: center;
  gap: 6px;
  font-weight: 500;
  transition: .2s;
}
.btn-nav:hover { border-color: var(--brand); color: var(--brand); }
.month-label { font-size: 18px; font-weight: 700; min-width: 140px; text-align: center; color: var(--text-primary); }

.toolbar-right { display: flex; align-items: center; gap: 10px; }
.search-box { position: relative; width: 200px; }
.search-icon { position: absolute; left: 10px; top: 50%; transform: translateY(-50%); color: var(--text-tertiary); }
.search-input { width: 100%; padding: 8px 12px 8px 32px; border: 1px solid var(--border-input); border-radius: var(--radius-sm); font-size: 13px; }
.date-input { padding: 7px 10px; border: 1px solid var(--border-input); border-radius: var(--radius-sm); font-size: 13px; }

.btn-tool { 
  display: flex; 
  align-items: center; 
  gap: 6px; 
  padding: 8px 16px; 
  border: 1px solid var(--border-strong); 
  background: white; 
  border-radius: var(--radius-sm); 
  cursor: pointer; 
  font-size: 14px; 
  text-decoration: none;
  color: var(--text-secondary);
  transition: .2s;
}
.btn-tool:hover { border-color: var(--brand); color: var(--brand); }
.btn-tool.btn-primary { background: var(--brand); color: var(--text-inverse); border-color: var(--brand); }

.calendar-grid-wrapper { 
  background: var(--bg-card); 
  border-radius: var(--radius-lg); 
  padding: 1px; 
  overflow: hidden; 
  border: 1px solid var(--border-base);
  box-shadow: var(--shadow-sm);
}

.cal-table { width: 100%; border-collapse: collapse; table-layout: fixed; }
.cal-table th { background: var(--bg-table-header); padding: 12px; font-size: 13px; font-weight: 600; color: var(--text-secondary); text-align: center; border-bottom: 1px solid var(--border-base); }
.cal-table td { padding: 0; text-align: center; vertical-align: top; height: 100px; cursor: pointer; border-bottom: 1px solid var(--border-base); border-right: 1px solid var(--border-base); transition: background .15s; position: relative; }
.cal-table td:last-child { border-right: none; }
.cal-table tr:last-child td { border-bottom: none; }

.day-cell-content { height: 100%; display: flex; flex-direction: column; padding: 10px; }
.day-num { font-size: 16px; font-weight: 500; color: var(--text-secondary); }
.cal-table td.other-month { opacity: 0.3; background: #fafafa; pointer-events: none; }
.cal-table td.past-day .day-num { color: var(--text-quaternary); }
.cal-table td.today { background: hsla(var(--brand-hue), var(--brand-sat), var(--brand-lit), 0.03); }
.cal-table td.today .day-num { background: var(--brand); color: white; width: 28px; height: 28px; line-height: 28px; border-radius: 50%; margin: 0 auto; }
.cal-table td.selected { background: hsla(var(--brand-hue), var(--brand-sat), var(--brand-lit), 0.08); }
.cal-table td.selected::after { content: ''; position: absolute; inset: 0; border: 2px solid var(--brand); pointer-events: none; }

.event-dots { display: flex; flex-wrap: wrap; gap: 4px; justify-content: center; margin-top: auto; padding-bottom: 4px; }
.dot { width: 6px; height: 6px; background: var(--brand); border-radius: 50%; }
.dot-past { background: var(--text-quaternary); }
.dot-more { font-size: 10px; color: var(--brand); font-weight: 600; }

.day-panel { margin-top: 16px; background: var(--bg-card); border-radius: var(--radius-lg); padding: 24px; box-shadow: var(--shadow-md); border: 1px solid var(--border-base); }
.panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
.panel-title { display: flex; align-items: center; gap: 10px; }
.title-icon { color: var(--brand); }
.panel-date { font-size: 18px; font-weight: 700; color: var(--text-primary); }

.timeline-container { padding: 0 10px; margin-bottom: 24px; }
.timeline { height: 48px; background: #f8f9fa; border-radius: var(--radius-md); position: relative; border: 1px solid var(--border-base); }
.tl-hours { display: flex; height: 100%; width: 100%; }
.tl-hour-label { flex: 1; text-align: center; font-size: 10px; color: var(--text-tertiary); border-left: 1px solid rgba(0,0,0,0.03); padding-top: 4px; font-family: monospace; }
.tl-dot { position: absolute; top: 20px; width: 12px; height: 12px; background: var(--brand); border-radius: 50%; transform: translateX(-50%); cursor: pointer; z-index: 1; box-shadow: 0 0 0 3px white; border: 1px solid var(--brand); }
.tl-dot:hover { transform: translateX(-50%) scale(1.3); z-index: 5; }
.tl-dot.tl-dot-past { background: #d9d9d9; border-color: #ccc; }
.tl-now-bar { position: absolute; top: 0; bottom: 0; width: 2px; background: var(--danger); z-index: 2; pointer-events: none; }

.event-cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 12px; }
.event-card { display: flex; background: white; border-radius: var(--radius-md); border: 1px solid var(--border-base); overflow: hidden; cursor: pointer; transition: all .2s; }
.event-card:hover { transform: translateY(-2px); box-shadow: var(--shadow-md); border-color: var(--brand); }
.event-card.card-selected { border-color: var(--brand); background: var(--bg-info); }
.card-side { width: 4px; flex-shrink: 0; }
.card-body { flex: 1; padding: 14px 16px; min-width: 0; }
.card-main { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; }
.card-title { font-weight: 600; font-size: 15px; color: var(--text-primary); }
.card-time { font-size: 12px; color: var(--text-secondary); display: flex; align-items: center; gap: 4px; white-space: nowrap; }

.empty-day-hint { grid-column: 1 / -1; text-align: center; padding: 40px; color: var(--text-tertiary); font-style: italic; }

.search-results-panel { padding: 20px; background: var(--bg-card); border-radius: var(--radius-lg); display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 16px; border: 1px solid var(--border-base); }
.card-date { font-size: 12px; color: var(--brand); margin-top: 6px; font-weight: 600; }

.ctx-menu { position: fixed; z-index: 1000; background: rgba(255,255,255,0.9); backdrop-filter: blur(10px); border: 1px solid var(--border-base); border-radius: var(--radius-md); box-shadow: var(--shadow-lg); min-width: 160px; padding: 6px; }
.ctx-item { padding: 10px 14px; font-size: 13px; cursor: pointer; display: flex; align-items: center; gap: 10px; border-radius: var(--radius-sm); color: var(--text-secondary); }
.ctx-item:hover { background: var(--brand); color: white; }
.ctx-divider { height: 1px; background: var(--border-base); margin: 4px 0; }
.ctx-item.danger:hover { background: var(--danger); }

.modal-overlay { position: fixed; inset: 0; z-index: 2000; background: rgba(0,0,0,0.4); display: flex; align-items: center; justify-content: center; backdrop-filter: blur(4px); }
.modal-card { background: white; border-radius: var(--radius-lg); min-width: 400px; max-width: 520px; box-shadow: var(--shadow-xl); overflow: hidden; border: 1px solid var(--glass-border); }
.modal-header { padding: 20px 24px; border-bottom: 1px solid var(--border-base); display: flex; justify-content: space-between; align-items: center; background: #fafafa; }
.btn-close-circle { border: none; background: transparent; cursor: pointer; color: var(--text-tertiary); display: flex; transition: .2s; }
.btn-close-circle:hover { color: var(--text-primary); transform: rotate(90deg); }

.modal-body { padding: 24px; display: flex; flex-direction: column; gap: 20px; }
.modal-row { display: flex; gap: 16px; }
.row-icon { color: var(--brand); margin-top: 2px; flex-shrink: 0; }
.row-val { font-size: 16px; font-weight: 600; color: var(--text-primary); line-height: 1.4; }
.row-label { font-size: 13px; color: var(--text-secondary); margin-top: 2px; }
.desc-text { white-space: pre-wrap; font-weight: normal; font-size: 14px; color: var(--text-secondary); }

.modal-footer { padding: 16px 24px; background: #fafafa; border-top: 1px solid var(--border-base); display: flex; gap: 12px; justify-content: flex-end; }
.btn-action { padding: 8px 20px; border-radius: var(--radius-sm); border: 1px solid var(--border-strong); background: white; cursor: pointer; display: flex; align-items: center; gap: 8px; font-size: 14px; transition: .2s; text-decoration: none; color: var(--text-primary); }
.btn-action:hover { border-color: var(--brand); color: var(--brand); }
.btn-danger { color: var(--danger); border-color: var(--danger-border); }
.btn-danger:hover { background: var(--bg-danger); }

.empty-hint { text-align: center; padding: 100px 0; color: var(--text-quaternary); }
.empty-icon { margin-bottom: 16px; opacity: 0.2; }
</style>
