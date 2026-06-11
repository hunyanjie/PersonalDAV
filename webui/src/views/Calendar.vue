<template>
  <div>
    <div class="toolbar">
      <button class="btn-plain" @click="monthOffset-=12">&lt;&lt;</button>
      <button class="btn-plain" @click="monthOffset--">&lt; 上月</button>
      <span class="month-label">{{ year }} 年 {{ month }} 月</span>
      <button class="btn-plain" @click="monthOffset++">下月 &gt;</button>
      <button class="btn-plain" @click="monthOffset+=12">&gt;&gt;</button>
      <span style="flex:1" />
      <input v-model="jumpDate" type="date" class="date-input" @change="jumpToDate" />
      <input v-model="searchQuery" class="search-input" placeholder="搜索日程..." @input="doSearch" />
      <router-link to="/calendar/new" class="btn-primary">+ 新建</router-link>
    </div>
    <div v-if="errorMsg" class="error-banner">{{ errorMsg }}</div>

    <!-- Month Grid -->
    <table class="cal-table">
      <thead><tr><th>一</th><th>二</th><th>三</th><th>四</th><th>五</th><th>六</th><th>日</th></tr></thead>
      <tbody>
        <tr v-for="(week, wi) in weeks" :key="wi">
          <td v-for="(day, di) in week" :key="di"
            :class="cellClass(day)"
            @click="day.current && selectDay(day)">
            <div class="day-num">{{ day.day }}</div>
            <div class="event-dots">
              <span v-for="e in day.events" :key="e.uid" class="dot" :class="{ 'dot-past': day.isPast || isEventPast(e) }" :title="e.summary || e.uid" />
            </div>
          </td>
        </tr>
      </tbody>
    </table>

    <!-- Timeline + Event List -->
    <div v-if="selectedDay && !searchQuery" class="day-panel">
      <div class="panel-header">
        <span class="panel-date">{{ selectedDay.year }}-{{ pad(selectedDay.month) }}-{{ pad(selectedDay.day) }}</span>
        <button class="btn-sm" @click="exportDay">导出今日日程</button>
      </div>

      <!-- Timeline -->
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
            <div class="card-title">{{ e.summary || '(无标题)' }}</div>
            <div class="card-time">{{ formatTime(e.dtstart) }} - {{ formatTime(e.dtend) }}</div>
            <div v-if="e.description" class="card-desc">{{ e.description }}</div>
          </div>
        </div>
        <div v-if="!dayEvents.length" class="empty-hint">当日无日程</div>
      </div>
    </div>

    <!-- Context Menu -->
    <div v-if="ctxMenu.show" class="ctx-menu" :style="{ top: ctxMenu.y + 'px', left: ctxMenu.x + 'px' }" @click.stop>
      <div class="ctx-item" @click="exportSelected">分享/导出</div>
      <div class="ctx-item" @click="editSelected" :class="{ disabled: ctxMenu.uids.length !== 1 }">编辑</div>
      <div class="ctx-item danger" @click="deleteSelected">删除</div>
    </div>

    <!-- Detail Modal -->
    <div v-if="detailEvent" class="modal-overlay" @click.self="detailEvent = null">
      <div class="modal-card">
        <div class="modal-header">
          <h3>{{ detailEvent.summary || '(无标题)' }}</h3>
          <button class="btn-plain close-btn" @click="detailEvent = null">&times;</button>
        </div>
        <div class="modal-body">
          <div class="modal-row"><label>时间</label><span>{{ formatTime(detailEvent.dtstart) }} - {{ formatTime(detailEvent.dtend) }}</span></div>
          <div v-if="detailEvent.description" class="modal-row"><label>描述</label><span>{{ detailEvent.description }}</span></div>
          <div v-if="detailEvent.location" class="modal-row"><label>地点</label><span>{{ detailEvent.location }}</span></div>
          <div v-if="detailEvent.categories" class="modal-row"><label>分类</label><span>{{ detailEvent.categories }}</span></div>
        </div>
        <div class="modal-actions">
          <button class="btn-sm" @click="exportSingle(detailEvent)">分享/导出</button>
          <router-link :to="`/calendar/${detailEvent.uid}/edit`" class="btn-sm">编辑</router-link>
          <button class="btn-sm btn-danger" @click="deleteSingle(detailEvent)">删除</button>
        </div>
      </div>
    </div>

    <p v-if="!events.length && !errorMsg && !selectedDay" class="empty-hint">当前月份无日程</p>
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

function icalDateToStr(s) {
  if (!s) return ''
  const m = s.match(/^(\d{4})-?(\d{2})-?(\d{2})/)
  return m ? `${m[1]}-${m[2]}-${m[3]}` : s.substring(0, 10)
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
    nowMonth() {
      const d = this.currentTime
      return new Date(d.getFullYear(), d.getMonth(), 1)
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
      if (this.searchQuery) return []
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
        const dayEvents = this.events.filter(e => {
          if (!e.dtstart) return false
          return icalDateToStr(e.dtstart) === dateStr
        })
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
        .filter(e => e.dtstart && icalDateToStr(e.dtstart) === dateStr)
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
    isEventEndedToday(e) {
      if (!this.isTodaySelected) return false
      const et = icalDateToObj(e.dtend)
      return et && et <= this.currentTime
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

    // Timeline
    eventLeft(e) {
      const st = icalDateToObj(e.dtstart)
      if (!st) return '0%'
      const h = toHours(st)
      return ((h / 24) * 100) + '%'
    },

    // Event card styling
    eventCardClass(e) {
      const st = eventStatus(e, this.currentTime)
      const isPastDay = !this.isTodaySelected && (icalDateToStr(e.dtstart) < this.todayStr)
      return {
        'card-ended': (st === 'ended' && this.isTodaySelected) || isPastDay,
        'card-ongoing': st === 'ongoing' && this.isTodaySelected,
        'card-upcoming': st === 'upcoming' || (!this.isTodaySelected && !isPastDay),
        'card-selected': this.selectedUids.includes(e.uid),
      }
    },
    cardSideStyle(e) {
      const st = eventStatus(e, this.currentTime)
      const isPastDay = !this.isTodaySelected && (icalDateToStr(e.dtstart) < this.todayStr)
      if (st === 'ended' || isPastDay) return { background: '#d9d9d9' }
      if (st === 'upcoming' || !this.isTodaySelected) return { background: 'var(--theme,#1677ff)' }
      
      const stDate = icalDateToObj(e.dtstart)
      const etDate = icalDateToObj(e.dtend)
      if (!stDate || !etDate) return { background: 'var(--theme,#1677ff)' }
      const total = etDate.getTime() - stDate.getTime()
      const elapsed = this.currentTime.getTime() - stDate.getTime()
      const pct = total > 0 ? Math.min(elapsed / total * 100, 100) : 100
      return { background: `linear-gradient(to bottom, #d9d9d9 ${pct}%, var(--theme,#1677ff) ${pct}%)` }
    },
    formatTime(s) {
      const d = icalDateToObj(s)
      if (!d) return s || ''
      const h = d.getHours()
      const m = pad(d.getMinutes())
      const ampm = h < 12 ? '上午' : '下午'
      const h12 = h === 0 ? 12 : (h > 12 ? h - 12 : h)
      return `${ampm} ${h12}:${m}`
    },

    // Card selection + multi-select
    onCardClick(e, ev) {
      if (ev.ctrlKey || ev.metaKey) {
        const idx = this.selectedUids.indexOf(e.uid)
        if (idx >= 0) this.selectedUids.splice(idx, 1)
        else this.selectedUids.push(e.uid)
        return
      }
      if (ev.shiftKey && this.selectedUids.length) {
        const all = this.dayEvents.map(x => x.uid)
        const lastIdx = all.indexOf(this.selectedUids[this.selectedUids.length - 1])
        const curIdx = all.indexOf(e.uid)
        if (lastIdx >= 0 && curIdx >= 0) {
          const [start, end] = lastIdx < curIdx ? [lastIdx, curIdx] : [curIdx, lastIdx]
          const range = all.slice(start, end + 1)
          this.selectedUids = [...new Set([...this.selectedUids, ...range])]
        }
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

    // Detail modal
    openDetail(e) { this.detailEvent = e; this.ctxMenu.show = false },

    // Export
    exportDay() {
      const text = this.dayEvents.map(e =>
        `${this.formatTime(e.dtstart)} - ${this.formatTime(e.dtend)}  ${e.summary || ''}`
      ).join('\n')
      navigator.clipboard.writeText(text).then(() => alert('日程已复制到剪贴板')).catch(() => {})
    },
    exportSingle(e) {
      const text = `${this.formatTime(e.dtstart)} - ${this.formatTime(e.dtend)}  ${e.summary || ''}`
      navigator.clipboard.writeText(text).then(() => {
        this.detailEvent = null; alert('已复制')
      }).catch(() => {})
    },
    exportSelected() {
      const items = this.dayEvents.filter(e => this.ctxMenu.uids.includes(e.uid))
      const text = items.map(e =>
        `${this.formatTime(e.dtstart)} - ${this.formatTime(e.dtend)}  ${e.summary || ''}`
      ).join('\n')
      navigator.clipboard.writeText(text).then(() => {
        this.ctxMenu.show = false; alert('已复制')
      }).catch(() => {})
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
  },
}
</script>

<style scoped>
.toolbar { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
.search-input { padding: 6px 12px; border: 1px solid #d9d9d9; border-radius: 6px; font-size: 13px; width: 180px; }
.date-input { padding: 5px 8px; border: 1px solid #d9d9d9; border-radius: 6px; font-size: 13px; }
.btn-plain { padding: 6px 14px; border: 1px solid #d9d9d9; background: #fff; border-radius: 6px; cursor: pointer; font-size: 13px; }
.month-label { font-size: 16px; font-weight: bold; min-width: 140px; text-align: center; }
.btn-primary { padding: 8px 16px; background: #1677ff; color: #fff; text-decoration: none; border-radius: 6px; font-size: 14px; display: inline-flex; align-items: center; }
.error-banner { background: #fff2f0; border: 1px solid #ffccc7; border-radius: 6px; padding: 8px 16px; color: #cf1322; margin-bottom: 12px; font-size: 13px; }
.empty-hint { text-align: center; color: #999; padding: 24px; font-size: 14px; }

/* Month Grid */
.cal-table { width: 100%; background: #fff; border-radius: 8px; border-collapse: collapse; box-shadow: 0 1px 4px rgba(0,0,0,.06); }
.cal-table th { background: #fafafa; padding: 8px; font-size: 13px; text-align: center; }
.cal-table td { padding: 6px; text-align: center; vertical-align: top; height: 64px; cursor: pointer; border-bottom: 1px solid #f0f0f0; transition: background .15s; }
.cal-table td.other-month { color: #ccc; }
.cal-table td.past-day { background: #f9f9f9; }
.cal-table td.past-day .day-num { color: #bbb; }
.cal-table td.has-event { background: #e6f4ff; border-bottom: 3px solid #1677ff; }
.cal-table td.selected .day-num { border: 2px solid #1677ff; color: #1677ff; border-radius: 50%; width: 28px; height: 28px; line-height: 24px; display: inline-block; }
.cal-table td.today .day-num { background: #1677ff; color: #fff; border-radius: 50%; width: 28px; height: 28px; line-height: 28px; display: inline-block; }
.day-num { font-size: 15px; font-weight: 500; display: inline-block; }
.event-dots { display: flex; flex-wrap: wrap; gap: 3px; justify-content: center; margin-top: 4px; }
.dot { width: 6px; height: 6px; background: #1677ff; border-radius: 50%; display: inline-block; }
.dot.dot-past { background: #bbb; }

/* Day panel */
.day-panel { margin-top: 16px; background: #fff; border-radius: 8px; padding: 16px; box-shadow: 0 1px 4px rgba(0,0,0,.06); }
.panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.panel-date { font-size: 16px; font-weight: bold; }

/* Timeline */
.timeline { height: 40px; margin-bottom: 16px; position: relative; user-select: none; }
.tl-hours { display: flex; height: 100%; width: 100%; }
.tl-hour-label { flex: 1; text-align: center; font-size: 11px; color: #999; border-left: 1px solid #eee; padding-top: 2px; }
.tl-dot { position: absolute; top: 16px; width: 10px; height: 10px; background: #1677ff; border-radius: 50%; transform: translateX(-50%); cursor: pointer; z-index: 1; }
.tl-dot.tl-dot-past { background: #bbb; }
.tl-now-bar { position: absolute; top: 0; bottom: 0; width: 2px; background: #1677ff; z-index: 2; pointer-events: none; transition: left 2s linear; }

/* Event Cards */
.event-cards { display: flex; flex-direction: column; gap: 8px; }
.event-card { display: flex; border-radius: 8px; overflow: hidden; cursor: pointer; border: 1px solid #f0f0f0; transition: box-shadow .15s, border-color .15s; }
.event-card:hover { box-shadow: 0 2px 8px rgba(0,0,0,.08); }
.event-card.card-selected { border-color: #1677ff; }
.card-side { width: 4px; flex-shrink: 0; }
.card-body { flex: 1; padding: 10px 14px; min-width: 0; }
.card-title { font-weight: 600; font-size: 14px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.card-time { font-size: 13px; margin-top: 2px; }
.card-desc { font-size: 12px; color: #888; margin-top: 4px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.card-ended .card-title { color: #999; }
.card-ended .card-time { color: #bbb; }
.card-ended .card-desc { color: #ccc; }
.card-ongoing .card-title { color: #000; }
.card-ongoing .card-time { color: #333; }
.card-upcoming .card-title { color: #000; }
.card-upcoming .card-time { color: #333; }

/* Context Menu */
.ctx-menu { position: fixed; z-index: 1000; background: #fff; border: 1px solid #e8e8e8; border-radius: 6px; box-shadow: 0 4px 12px rgba(0,0,0,.12); min-width: 120px; padding: 4px 0; }
.ctx-item { padding: 8px 16px; font-size: 13px; cursor: pointer; }
.ctx-item:hover { background: #f5f5f5; }
.ctx-item.disabled { color: #ccc; cursor: default; }
.ctx-item.danger { color: #cf1322; }
.ctx-item.danger:hover { background: #fff2f0; }

/* Modal */
.modal-overlay { position: fixed; inset: 0; z-index: 999; background: rgba(0,0,0,.4); display: flex; align-items: center; justify-content: center; }
.modal-card { background: #fff; border-radius: 12px; min-width: 360px; max-width: 480px; box-shadow: 0 8px 24px rgba(0,0,0,.15); overflow: hidden; }
.modal-header { display: flex; justify-content: space-between; align-items: center; padding: 16px 20px; border-bottom: 1px solid #f0f0f0; }
.modal-header h3 { margin: 0; font-size: 16px; }
.modal-body { padding: 16px 20px; }
.modal-row { display: flex; gap: 8px; margin-bottom: 8px; font-size: 14px; }
.modal-row label { color: #888; min-width: 48px; flex-shrink: 0; }
.modal-actions { display: flex; gap: 8px; padding: 12px 20px; border-top: 1px solid #f0f0f0; }
.modal-actions .btn-sm { padding: 6px 16px; border-radius: 6px; font-size: 13px; text-decoration: none; border: 1px solid #d9d9d9; background: #fff; cursor: pointer; }
.btn-danger { color: #cf1322; border-color: #ffa39e; }
</style>
