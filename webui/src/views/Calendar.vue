<template>
  <div>
    <div class="toolbar">
      <button class="btn-plain" @click="monthOffset--">&lt; 上月</button>
      <span class="month-label">{{ year }} 年 {{ month }} 月</span>
      <button class="btn-plain" @click="monthOffset++">下月 &gt;</button>
      <span style="flex:1" />
      <input v-model="searchQuery" class="search-input" placeholder="搜索日程..." @input="doSearch" />
      <router-link to="/calendar/new" class="btn-primary">+ 新建</router-link>
    </div>
    <table class="cal-table">
      <thead>
        <tr><th>一</th><th>二</th><th>三</th><th>四</th><th>五</th><th>六</th><th>日</th></tr>
      </thead>
      <tbody>
        <tr v-for="(week, wi) in weeks" :key="wi">
          <td v-for="(day, di) in week" :key="di"
            :class="{ 'other-month': !day.current, 'has-event': day.hasEvent }"
            @click="day.current && showDay(day.day)">
            <div class="day-num">{{ day.day }}</div>
            <div class="event-dots">
              <span v-for="e in day.events" :key="e.uid" class="dot" :title="e.summary || e.uid" />
            </div>
          </td>
        </tr>
      </tbody>
    </table>
    <div v-if="selectedDay" class="day-events">
      <h4>{{ selectedDay.year }}-{{ selectedDay.month }}-{{ selectedDay.day }} 的事件</h4>
      <div v-for="e in selectedDay.events" :key="e.uid" class="event-row">
        <span>{{ e.summary || e.uid }}</span>
        <router-link :to="`/calendar/${e.uid}/edit`" class="btn-sm">编辑</router-link>
      </div>
      <p v-if="!selectedDay.events.length">暂无事件</p>
    </div>
  </div>
</template>

<script>
import api from '../api.js'

function icalDateToStr(dtstart) {
  if (!dtstart) return ''
  const m = dtstart.match(/^(\d{4})(\d{2})(\d{2})/)
  return m ? `${m[1]}-${m[2]}-${m[3]}` : dtstart.substring(0, 10)
}

export default {
  data: () => ({ events: [], monthOffset: 0, selectedDay: null, searchQuery: '', _searchTimer: null }),
  watch: {
    monthOffset() { this.selectedDay = null; this.load() },
  },
  computed: {
    now() { const d = new Date(); return new Date(d.getFullYear(), d.getMonth() + this.monthOffset, 1) },
    year() { return this.now.getFullYear() },
    month() { return this.now.getMonth() + 1 },
    weeks() {
      const y = this.now.getFullYear(), m = this.now.getMonth()
      const first = new Date(y, m, 1).getDay() || 7
      const daysInMonth = new Date(y, m + 1, 0).getDate()
      const daysInPrev = new Date(y, m, 0).getDate()
      const weeks = []; let row = []
      const prev = daysInPrev - first + 2
      for (let i = prev; i <= daysInPrev; i++) row.push({ day: i, current: false, hasEvent: false, events: [] })
      for (let d = 1; d <= daysInMonth; d++) {
        const dateStr = `${y}-${String(m+1).padStart(2,'0')}-${String(d).padStart(2,'0')}`
        const dayEvents = this.events.filter(e => {
          if (!e.dtstart) return false
          const ds = icalDateToStr(e.dtstart)
          return ds === dateStr
        })
        row.push({ day: d, current: true, hasEvent: dayEvents.length > 0, events: dayEvents })
        if (row.length === 7) { weeks.push(row); row = [] }
      }
      if (row.length) {
        for (let d = 1; row.length < 7; d++) row.push({ day: d, current: false, hasEvent: false, events: [] })
        weeks.push(row)
      }
      return weeks
    },
  },
  methods: {
    async load() {
      try {
        const res = await api.listEvents(0, 500)
        this.events = Array.isArray(res) ? res : (res.items || [])
      } catch(e) { this.events = [] }
    },
    doSearch() {
      clearTimeout(this._searchTimer)
      this._searchTimer = setTimeout(() => {
        if (this.searchQuery.trim()) {
          api.searchEvents(this.searchQuery, '', '', 200).then(results => {
            this.events = Array.isArray(results) ? results : (results.items || [])
          }).catch(() => {})
        } else {
          this.load()
        }
      }, 300)
    },
    showDay(day) {
      const dateStr = `${this.year}-${String(this.month).padStart(2,'0')}-${String(day).padStart(2,'0')}`
      this.selectedDay = {
        year: this.year, month: this.month, day,
        events: this.events.filter(e => {
          if (!e.dtstart) return false
          return icalDateToStr(e.dtstart) === dateStr
        }),
      }
    },
  },
}
</script>

<style scoped>
.toolbar { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
.search-input { padding: 6px 12px; border: 1px solid #d9d9d9; border-radius: 6px; font-size: 13px; width: 180px; }
.btn-plain { padding: 6px 14px; border: 1px solid #d9d9d9; background: #fff; border-radius: 6px; cursor: pointer; font-size: 13px; }
.month-label { font-size: 16px; font-weight: bold; min-width: 140px; text-align: center; }
.btn-primary { padding: 8px 16px; background: #1677ff; color: #fff; text-decoration: none; border-radius: 6px; font-size: 14px; }
.cal-table { width: 100%; background: #fff; border-radius: 8px; border-collapse: collapse; box-shadow: 0 1px 4px rgba(0,0,0,.06); }
.cal-table th { background: #fafafa; padding: 8px; font-size: 13px; text-align: center; }
.cal-table td { padding: 6px; text-align: center; vertical-align: top; height: 60px; cursor: pointer; border-bottom: 1px solid #f0f0f0; }
.cal-table td.other-month { color: #ccc; }
.cal-table td.has-event { background: #e6f4ff; }
.day-num { font-size: 14px; }
.event-dots { display: flex; flex-wrap: wrap; gap: 3px; justify-content: center; margin-top: 4px; }
.dot { width: 6px; height: 6px; background: #1677ff; border-radius: 50%; display: inline-block; }
.day-events { background: #fff; border-radius: 8px; padding: 16px; margin-top: 16px; box-shadow: 0 1px 4px rgba(0,0,0,.06); }
.day-events h4 { margin: 0 0 12px; font-size: 15px; }
.event-row { display: flex; gap: 12px; align-items: center; padding: 6px 0; border-bottom: 1px solid #f5f5f5; }
.btn-sm { padding: 4px 12px; border-radius: 4px; font-size: 13px; text-decoration: none; border: 1px solid #d9d9d9; background: #fff; }
</style>
