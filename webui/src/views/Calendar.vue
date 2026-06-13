<template>
  <div class="calendar-page">
    <div class="toolbar glass">
      <div class="toolbar-left">
        <div class="nav-controls">
          <button class="btn-icon" @click="monthOffset-=12" title="上一年"><ChevronsLeft :size="18" /></button>
          <button class="btn-nav" @click="monthOffset--"><ChevronLeft :size="18" /> <span class="hide-mobile">上月</span></button>
          <span class="month-label">{{ year }} 年 {{ month }} 月</span>
          <button class="btn-nav" @click="monthOffset++"><span class="hide-mobile">下月</span> <ChevronRight :size="18" /></button>
          <button class="btn-icon" @click="monthOffset+=12" title="下一年"><ChevronsRight :size="18" /></button>
        </div>
      </div>
      
      <div class="toolbar-center">
        <div class="search-shell">
          <Search :size="16" class="search-icon" />
          <input v-model="searchQuery" class="search-input" placeholder="搜索日程..." @input="doSearch" />
        </div>
      </div>
      
      <div class="toolbar-right">
        <div class="input-group">
          <input v-model="jumpDate" type="date" class="date-input" @change="jumpToDate" />
        </div>
        <div class="action-group">
          <label class="btn-tool btn-import">
            <Download :size="18" /> <span class="hide-mobile">导入</span>
            <input type="file" accept=".ics" @change="doImportICS" hidden />
          </label>
          <router-link to="/calendar/new" class="btn-tool btn-primary">
            <Plus :size="18" /> <span class="hide-mobile">新建</span>
          </router-link>
        </div>
      </div>
    </div>

    <div v-if="errorMsg" class="error-banner">
      <AlertCircle :size="16" /> {{ errorMsg }}
    </div>

    <!-- Calendar Grid -->
    <transition name="fade">
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
                    <span v-for="e in day.events.slice(0, 999)" :key="e.uid" class="dot" :class="{ 'dot-past': isEventPast(e) }" :title="e.summary || e.uid" />
                    <span v-if="day.events.length > 999" class="dot-more">+{{ day.events.length - 999 }}</span>
                  </div>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </transition>

    <!-- Day Panel -->
    <transition name="modal">
      <div v-if="selectedDay && !searchQuery" class="day-panel glass no-transition">
        <div class="panel-header">
          <div class="panel-title">
            <CalendarDays :size="20" class="title-icon" />
            <span class="panel-date">{{ selectedDay.year }}年{{ pad(selectedDay.month) }}月{{ pad(selectedDay.day) }}日</span>
          </div>
          <button class="btn-sm btn-tool" @click="exportDay"><Share2 :size="14" /> <span class="hide-mobile">导出今日</span></button>
        </div>

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

        <div class="event-cards">
          <div v-for="e in dayEvents" :key="e.uid"
            class="event-card"
            :class="eventCardClass(e)"
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
          <div v-if="!dayEvents.length" class="empty-day-hint">当日无日程</div>
        </div>
      </div>
    </transition>

    <!-- Search Results -->
    <transition name="fade">
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
        <div v-if="!events.length" class="empty-hint">未找到相关日程</div>
      </div>
    </transition>

    <!-- Detail Modal -->
    <transition name="modal">
      <div v-if="detailEvent" class="modal-overlay" @click.self="detailEvent = null">
        <div class="modal-card glass no-transition">
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
              <div class="row-content"><div class="row-val">{{ detailEvent.location }}</div></div>
            </div>
            <div v-if="detailEvent.categories" class="modal-row">
              <Layers :size="18" class="row-icon" />
              <div class="row-content"><div class="row-val">{{ detailEvent.categories }}</div></div>
            </div>
            <div v-if="detailEvent.description" class="modal-row">
              <FileText :size="18" class="row-icon" />
              <div class="row-content"><div class="row-val desc-text">{{ detailEvent.description }}</div></div>
            </div>
          </div>
          <div class="modal-footer">
            <button class="btn-action" @click="exportSingle(detailEvent)"><Share2 :size="14" /> 导出</button>
            <router-link :to="`/calendar/${detailEvent.uid}/edit`" class="btn-action"><Pencil :size="14" /> 编辑</router-link>
            <button class="btn-action btn-danger" @click="deleteSingle(detailEvent)"><Trash2 :size="14" /> 删除</button>
          </div>
        </div>
      </div>
    </transition>
  </div>
</template>

<script>
import { 
  ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, Search, 
  Download, Plus, AlertCircle, CalendarDays, Share2, Clock, 
  MapPin, Layers, FileText, X, Calendar as CalendarIcon
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
    MapPin, Layers, FileText, X, CalendarIcon
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
        this.errorMsg = '加载日程失败'
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
      const isPastDay = !this.isTodaySelected && (icalDateToStr(e.dtend) || icalDateToStr(e.dtstart)) < this.todayStr
      return {
        'card-ended': (st === 'ended' && this.isTodaySelected) || isPastDay,
        'card-ongoing': st === 'ongoing' && this.isTodaySelected,
        'card-selected': this.selectedUids.includes(e.uid),
      }
    },
    cardSideStyle(e) {
      const st = eventStatus(e, this.currentTime)
      const isPastDay = (icalDateToStr(e.dtend) || icalDateToStr(e.dtstart)) < this.todayStr
      if (st === 'ended' || isPastDay) return { background: '#d9d9d9' }
      if (st === 'upcoming') return { background: 'var(--brand)' }
      
      const stDate = icalDateToObj(e.dtstart), etDate = icalDateToObj(e.dtend)
      if (!stDate || !etDate) return { background: 'var(--brand)' }
      const total = etDate - stDate, elapsed = this.currentTime - stDate
      const pct = total > 0 ? Math.min(elapsed / total * 100, 100) : 100
      return { background: `linear-gradient(to bottom, #d9d9d9 ${pct}%, var(--brand) ${pct}%)` }
    },
    formatTime(s) {
      const d = icalDateToObj(s)
      return d ? d.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' }) : s || ''
    },
    formatDateFull(s) {
      const d = icalDateToObj(s)
      return d ? d.toLocaleDateString('zh-CN', { year: 'numeric', month: 'long', day: 'numeric', weekday: 'long' }) : ''
    },
    onCardClick(e, ev) {
      if (ev.ctrlKey || ev.metaKey) {
        const idx = this.selectedUids.indexOf(e.uid)
        if (idx >= 0) this.selectedUids.splice(idx, 1); else this.selectedUids.push(e.uid)
        return
      }
      this.selectedUids = [e.uid]; this.openDetail(e)
    },
    onContextMenu(e, ev) {
      if (!this.selectedUids.includes(e.uid)) this.selectedUids = [e.uid]
      this.ctxMenu = { show: true, x: ev.clientX, y: ev.clientY, uids: [...this.selectedUids] }
    },
    onClickAway() { this.ctxMenu.show = false },
    openDetail(e) { this.detailEvent = e; this.ctxMenu.show = false },
    _toICS(events) {
      const vevents = events.map(e => [
        'BEGIN:VEVENT', `UID:${e.uid || ''}`,
        `DTSTART:${(e.dtstart || '').replace(/[-:]/g, '')}`,
        `DTEND:${(e.dtend || '').replace(/[-:]/g, '')}`,
        `SUMMARY:${e.summary || ''}`,
        e.description ? `DESCRIPTION:${e.description}` : '',
        'END:VEVENT',
      ].filter(Boolean).join('\r\n')).join('\r\n')
      return `BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//PersonalDAV//CN\r\n${vevents}\r\nEND:VCALENDAR`
    },
    _downloadIcs(content, name) {
      const blob = new Blob([content], { type: 'text/calendar;charset=utf-8' })
      const url = URL.createObjectURL(blob); const a = document.createElement('a')
      a.href = url; a.download = name; a.click(); URL.revokeObjectURL(url)
    },
    exportDay() { this._downloadIcs(this._toICS(this.dayEvents), `日程_${this.todayStr}.ics`) },
    exportSingle(e) { this._downloadIcs(this._toICS([e]), `${e.summary || '日程'}.ics`); this.detailEvent = null },
    exportSelected() {
      const items = this.dayEvents.filter(x => this.ctxMenu.uids.includes(x.uid))
      this._downloadIcs(this._toICS(items), `日程_${Date.now()}.ics`); this.ctxMenu.show = false
    },
    editSelected() { if (this.ctxMenu.uids.length === 1) this.$router.push(`/calendar/${this.ctxMenu.uids[0]}/edit`) },
    async deleteSelected() {
      if (!await window.showConfirm({ message: `确认删除选中的 ${this.ctxMenu.uids.length} 个日程？`, type: 'danger' })) return
      Promise.all(this.ctxMenu.uids.map(uid => api.deleteEvent(uid))).then(() => { this.ctxMenu.show = false; this.load() })
    },
    async deleteSingle(e) {
      if (!await window.showConfirm({ message: '确认删除此日程？', type: 'danger' })) return
      api.deleteEvent(e.uid).then(() => { this.detailEvent = null; this.load() })
    },
    async doImportICS(e) {
      const file = e.target.files[0]; if (!file) return
      try {
        const text = await file.text(); const blocks = text.split(/(?=BEGIN:VEVENT)/).filter(Boolean)
        for (const block of blocks) {
          const ical = `BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//PersonalDAV//CN\r\n${block.trim()}\r\nEND:VCALENDAR`
          await api.createEvent(ical)
        }
        this.load()
      } catch(e) { window.showToast('导入失败', 'error') }
      e.target.value = ''
    },
  },
}
</script>

<style scoped>
.calendar-page { display: flex; flex-direction: column; gap: 16px; height: 100%; }

.toolbar { 
  display: flex; 
  flex-wrap: wrap;
  align-items: center; 
  justify-content: space-between; 
  background: var(--bg-card); 
  padding: 12px 20px; 
  border-radius: var(--radius-lg); 
  box-shadow: var(--shadow-sm); 
  border: 1px solid var(--border-base);
  gap: 16px;
  position: sticky;
  top: 0;
  z-index: 100;
  backdrop-filter: blur(12px);
}

.toolbar-left, .toolbar-right { display: flex; align-items: center; gap: 12px; }
.action-group { display: flex; flex: 1; gap: 8px; }
.toolbar-center { flex: 1; display: flex; justify-content: center; min-width: 240px; }

.nav-controls { display: flex; align-items: center; gap: 8px; }
.btn-nav, .btn-icon, .btn-tool { 
  padding: 8px 16px; 
  border: 1px solid var(--border-strong); 
  background: white; 
  border-radius: var(--radius-sm); 
  cursor: pointer; 
  font-size: 14px; 
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  font-weight: 600;
  transition: all .2s cubic-bezier(0.34, 1.56, 0.64, 1);
  color: var(--text-secondary);
  text-decoration: none;
}

.btn-import { flex: 1; }
.btn-icon { padding: 8px; width: 38px; height: 38px; }
.btn-nav:hover, .btn-icon:hover, .btn-tool:hover { border-color: var(--brand); color: var(--brand); background: var(--bg-info); transform: translateY(-1px); }
.btn-primary { background: var(--brand); color: var(--text-inverse); border-color: var(--brand); flex: 1; }
.btn-primary:hover { opacity: 0.9; box-shadow: 0 4px 12px hsla(var(--brand-hue) var(--brand-sat) var(--brand-lit) / 0.2); }

.month-label { font-size: 18px; font-weight: 800; min-width: 120px; text-align: center; color: var(--text-primary); letter-spacing: -0.5px; }

.search-shell {
  display: flex;
  align-items: center;
  width: 100%;
  max-width: 400px;
  position: relative;
  transition: all .25s ease;
}
.search-icon { position: absolute; left: 12px; top: 50%; transform: translateY(-50%); color: var(--text-tertiary); }
.search-input { width: 100%; padding: 10px 12px 10px 36px; border: 1px solid var(--border-input); border-radius: var(--radius-md); font-size: 14px; outline: none; background: #fafafa; transition: all .2s; }
.search-input:focus { border-color: var(--brand); background: white; box-shadow: 0 0 0 3px var(--brand-ring); }
.date-input { padding: 9px 10px; border: 1px solid var(--border-input); border-radius: var(--radius-md); font-size: 13px; outline: none; background: #fafafa; }

.calendar-grid-wrapper { 
  background: var(--bg-card); 
  border-radius: var(--radius-lg); 
  padding: 1px; 
  overflow-y: auto;
  overflow-x: hidden;
  border: 1px solid var(--border-base);
  box-shadow: var(--shadow-sm);
  flex: 1;
  min-height: 300px;
}

.cal-table { width: 100%; height: 100%; border-collapse: collapse; table-layout: fixed; }
.cal-table th { background: var(--bg-table-header); padding: 12px; font-size: 13px; font-weight: 700; color: var(--text-secondary); text-align: center; border-bottom: 1px solid var(--border-base); }
.cal-table td { padding: 0; text-align: center; vertical-align: top; cursor: pointer; border-bottom: 1px solid var(--border-base); border-right: 1px solid var(--border-base); transition: all .2s; position: relative; min-height: 80px; }
.cal-table td:last-child { border-right: none; }
.cal-table td:hover:not(.other-month) { background: var(--bg-hover); z-index: 2; box-shadow: inset 0 0 0 2px var(--brand-ring); }

.day-cell-content { display: flex; flex-direction: column; padding: 6px; gap: 2px; height: 100%; justify-content: flex-start; }
.day-num { font-size: 14px; font-weight: 600; color: var(--text-secondary); transition: all .2s; flex-shrink: 0; margin-bottom: 2px; }
.cal-table td.other-month { opacity: 0.2; background: #fafafa; pointer-events: none; }
.cal-table td.today .day-num { background: var(--brand); color: white; width: 30px; height: 30px; line-height: 30px; border-radius: 50%; margin: 0 auto; box-shadow: 0 4px 8px var(--brand-ring); }
.cal-table td.selected { background: hsla(var(--brand-hue), var(--brand-sat), var(--brand-lit), 0.08); }
.cal-table td.selected::after { content: ''; position: absolute; inset: 0; border: 2px solid var(--brand); pointer-events: none; border-radius: 2px; }

.event-dots { display: flex; flex-wrap: wrap; gap: 3px; justify-content: center; padding: 0 2px; align-content: flex-start; flex: 1; overflow: hidden; }
.dot { width: 6px; height: 6px; background: var(--brand); border-radius: 50%; transition: all .2s; flex-shrink: 0; box-shadow: 0 0 0 1px white; }
.dot-past { background: #d9d9d9; }
.dot-more { font-size: 11px; color: var(--brand); font-weight: 800; margin-top: -2px; white-space: nowrap; }

.day-panel { margin-top: 16px; background: var(--bg-card); border-radius: var(--radius-lg); padding: 24px; box-shadow: var(--shadow-md); border: 1px solid var(--border-base); }
.panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
.panel-title { display: flex; align-items: center; gap: 12px; }
.title-icon { color: var(--brand); }
.panel-date { font-size: 20px; font-weight: 800; color: var(--text-primary); letter-spacing: -0.5px; }

.timeline-container { padding: 0 4px; margin-bottom: 28px; }
.timeline { height: 56px; background: #f9f9f9; border-radius: var(--radius-md); position: relative; border: 1px solid var(--border-base); box-shadow: inset 0 2px 4px rgba(0,0,0,0.02); }
.tl-hours { display: flex; height: 100%; width: 100%; }
.tl-hour-label { flex: 1; text-align: center; font-size: 10px; color: var(--text-tertiary); border-left: 1px solid rgba(0,0,0,0.04); padding-top: 6px; font-family: 'Fira Code', monospace; }
.tl-dot { position: absolute; top: 22px; width: 14px; height: 14px; background: var(--brand); border-radius: 50%; transform: translateX(-50%); cursor: pointer; z-index: 5; box-shadow: 0 0 0 4px white, 0 2px 8px rgba(0,0,0,0.1); border: 1px solid var(--brand); transition: all .2s cubic-bezier(0.175, 0.885, 0.32, 1.275); }
.tl-dot:hover { transform: translateX(-50%) scale(1.4); z-index: 10; box-shadow: 0 0 0 6px white, 0 4px 12px rgba(0,0,0,0.2); }
.tl-dot.tl-dot-past { background: #d9d9d9; border-color: #ccc; }
.tl-now-bar { position: absolute; top: 0; bottom: 0; width: 3px; background: var(--danger); z-index: 6; pointer-events: none; box-shadow: 0 0 8px rgba(255,77,79,0.5); }

.event-cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 16px; }
.event-card { display: flex; background: white; border-radius: var(--radius-md); border: 1px solid var(--border-base); overflow: hidden; cursor: pointer; transition: all .2s ease; box-shadow: var(--shadow-sm); }
.event-card:hover { transform: translateY(-3px) scale(1.01); box-shadow: var(--shadow-md); border-color: var(--brand); }

.card-side { width: 5px; flex-shrink: 0; }
.card-body { flex: 1; padding: 16px 20px; min-width: 0; }
.card-main { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; }
.card-title { font-weight: 700; font-size: 15px; color: var(--text-primary); }
.card-time { font-size: 12px; color: var(--text-secondary); display: flex; align-items: center; gap: 6px; white-space: nowrap; font-weight: 600; background: var(--bg-hover); padding: 4px 8px; border-radius: 4px; }

.empty-day-hint { grid-column: 1 / -1; text-align: center; padding: 48px; color: var(--text-tertiary); font-style: italic; background: #fafafa; border-radius: var(--radius-md); border: 2px dashed var(--border-base); }

.search-results-panel { padding: 24px; background: var(--bg-card); border-radius: var(--radius-lg); display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 20px; border: 1px solid var(--border-base); }
.card-date { font-size: 13px; color: var(--brand); margin-top: 8px; font-weight: 700; display: inline-block; }

.ctx-menu { position: fixed; z-index: 3000; background: rgba(255,255,255,0.95); backdrop-filter: blur(12px); border: 1px solid var(--border-base); border-radius: var(--radius-md); box-shadow: var(--shadow-lg); min-width: 180px; padding: 8px; border: 1px solid rgba(0,0,0,0.05); }
.ctx-item { padding: 12px 16px; font-size: 14px; cursor: pointer; display: flex; align-items: center; gap: 12px; border-radius: var(--radius-sm); color: var(--text-secondary); font-weight: 500; transition: .2s; }
.ctx-item:hover { background: var(--brand); color: white; transform: translateX(4px); }
.ctx-divider { height: 1px; background: var(--border-base); margin: 4px 0; }
.ctx-item.danger:hover { background: var(--danger); }

.modal-overlay { position: fixed; inset: 0; z-index: 4000; background: rgba(0,0,0,0.4); display: flex; align-items: center; justify-content: center; backdrop-filter: blur(8px); }
.modal-card { background: white; border-radius: var(--radius-xl); min-width: 440px; max-width: 560px; box-shadow: var(--shadow-xl); overflow: hidden; border: 1px solid var(--glass-border); }
.modal-header { padding: 24px 32px; border-bottom: 1px solid var(--border-base); display: flex; justify-content: space-between; align-items: center; background: #fafafa; }
.modal-header h3 { margin: 0; font-size: 20px; font-weight: 800; letter-spacing: -0.5px; }
.btn-close-circle { border: none; background: transparent; cursor: pointer; color: var(--text-tertiary); display: flex; transition: .3s cubic-bezier(0.4, 0, 0.2, 1); padding: 4px; }
.btn-close-circle:hover { color: var(--text-primary); transform: rotate(90deg) scale(1.2); }

.modal-body { padding: 32px; display: flex; flex-direction: column; gap: 28px; }
.modal-row { display: flex; gap: 20px; }
.row-icon { color: var(--brand); margin-top: 4px; flex-shrink: 0; opacity: 0.8; }
.row-val { font-size: 17px; font-weight: 700; color: var(--text-primary); line-height: 1.5; }
.row-label { font-size: 14px; color: var(--text-secondary); margin-top: 4px; font-weight: 500; }
.desc-text { white-space: pre-wrap; font-weight: 500; font-size: 15px; color: var(--text-secondary); line-height: 1.6; }

.modal-footer { padding: 20px 32px; background: #fafafa; border-top: 1px solid var(--border-base); display: flex; gap: 14px; justify-content: flex-end; }
.btn-action { padding: 10px 24px; border-radius: var(--radius-md); border: 1px solid var(--border-strong); background: white; cursor: pointer; display: flex; align-items: center; gap: 10px; font-size: 14px; font-weight: 700; transition: .2s; text-decoration: none; color: var(--text-primary); }
.btn-action:hover { border-color: var(--brand); color: var(--brand); transform: translateY(-2px); box-shadow: var(--shadow-sm); }
.btn-danger { color: var(--danger); border-color: var(--danger-border); }
.btn-danger:hover { background: var(--bg-danger); border-color: var(--danger); }

.empty-hint { text-align: center; padding: 120px 0; color: var(--text-quaternary); }
.empty-icon { margin-bottom: 16px; opacity: 0.15; }

/* Interactive feedback */
button:active, .btn-icon:active, .btn-nav:active, .btn-tool:active { transform: scale(0.95); opacity: 0.8; }

@media (max-width: 1100px) {
  .toolbar { flex-direction: column; align-items: stretch; padding: 16px; }
  .toolbar-left, .toolbar-right, .toolbar-center { width: 100%; justify-content: center; }
  .toolbar-center { order: 2; margin: 8px 0; }
  .toolbar-right { order: 3; justify-content: space-between; }
  .search-shell { max-width: none; }
}

@media (max-width: 768px) {
  .hide-mobile { display: none; }
  .toolbar { gap: 10px; }
  .nav-controls { width: 100%; justify-content: space-between; }
  .month-label { font-size: 16px; min-width: 80px; }
  .btn-nav, .btn-icon { padding: 8px; height: 34px; min-width: 34px; }
  .btn-nav { flex: 1; }
  
  .toolbar-right { flex-direction: row; align-items: center; }
  .action-group { justify-content: flex-end; }
  .date-input { flex: 1; min-width: 0; }

  .calendar-grid-wrapper { min-height: 320px; }
  .cal-table td { height: 60px; min-height: 60px; }
  .day-num { font-size: 13px; }
  .day-cell-content { padding: 6px; }
  .event-dots { gap: 2px; padding-bottom: 4px; }
  .dot { width: 5px; height: 5px; }
  
  .modal-card { min-width: 100vw; height: 100vh; border-radius: 0; margin: 0; }
  .event-cards { grid-template-columns: 1fr; }
}
</style>
