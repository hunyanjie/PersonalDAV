<template>
  <div class="schedule-layout">
    <!-- Left: Virtual scroll list -->
    <div class="schedule-list" ref="listRef" @scroll="onScroll">
      <div class="vl-total" :style="{ height: totalHeight + 'px' }">
        <div v-for="item in visibleItems" :key="item.key"
          class="vl-row"
          :class="{ 'vl-date-header': item.type === 'header', 'vl-event': item.type === 'event', 'vl-selected': item.type === 'event' && selectedUid === item.uid }"
          :style="{ transform: 'translateY(' + item.top + 'px)' }"
          @click="item.type === 'event' && selectEvent(item.uid)">
          <template v-if="item.type === 'header'">
            <div class="dh-date">{{ item.label }}</div>
            <div class="dh-lunar" v-if="item.lunar">{{ item.lunar }}</div>
          </template>
          <template v-else>
            <div class="ev-time">{{ item.time }}</div>
            <div class="ev-body">
              <div class="ev-title">{{ item.summary || '(无标题)' }}</div>
              <div class="ev-range">{{ item.range }}</div>
            </div>
          </template>
        </div>
      </div>
      <div v-if="loading" class="vl-loading">加载中...</div>
    </div>

    <!-- Right: Detail panel -->
    <div class="schedule-detail" v-if="selectedEvent">
      <h3>{{ selectedEvent.summary || '(无标题)' }}</h3>
      <div class="sd-row"><label>时间</label><span>{{ fmtTime(selectedEvent.dtstart) }} - {{ fmtTime(selectedEvent.dtend) }}</span></div>
      <div v-if="selectedEvent.description" class="sd-row"><label>描述</label><span>{{ selectedEvent.description }}</span></div>
      <div v-if="selectedEvent.location" class="sd-row"><label>地点</label><span>{{ selectedEvent.location }}</span></div>
      <div class="sd-actions">
        <button class="btn-sm" @click="exportSingle">分享/导出</button>
        <router-link :to="'/calendar/' + selectedEvent.uid + '/edit'" class="btn-sm">编辑</router-link>
        <button class="btn-sm btn-danger" @click="deleteSingle">删除</button>
      </div>
    </div>
    <div class="schedule-detail empty" v-else>
      <p>{{ selectedUid ? '请选择单个日程查看详情' : '点击左侧日程查看详情' }}</p>
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

function fmtDate(s) {
  const d = icalDateToObj(s)
  if (!d) return ''
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

const DAY_MS = 86400000
const ITEM_HEIGHT = 76
const HEADER_HEIGHT = 40
const OVERSCAN = 20

export default {
  data: () => ({
    events: [],
    loading: false,
    scrollTop: 0,
    containerHeight: 600,
    selectedUid: '',
    selectedEvent: null,
    _loadTimer: null,
    _loadedRange: { start: '', end: '' },
  }),
  mounted() {
    this.$nextTick(() => {
      if (this.$refs.listRef) {
        this.containerHeight = this.$refs.listRef.clientHeight
        this.loadRange()
      }
    })
    window.addEventListener('resize', this.onResize)
  },
  beforeUnmount() {
    window.removeEventListener('resize', this.onResize)
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
      return keys.map(k => ({ ...groups[k], events: groups[k].events.sort((a, b) => (a.dtstart || '').localeCompare(b.dtstart || '')) }))
    },
    virtualItems() {
      const items = []
      let top = 0
      for (const g of this.grouped) {
        items.push({ type: 'header', key: 'h-' + g.date, top, label: g.date, lunar: g.lunar, height: HEADER_HEIGHT })
        top += HEADER_HEIGHT
        for (const e of g.events) {
          items.push({
            type: 'event', key: 'e-' + e.uid, top, uid: e.uid,
            summary: e.summary, time: fmtTime(e.dtstart),
            range: fmtTime(e.dtstart) + ' - ' + fmtTime(e.dtend),
            height: ITEM_HEIGHT,
          })
          top += ITEM_HEIGHT
        }
      }
      return items
    },
    totalHeight() {
      return this.virtualItems.reduce((s, i) => s + i.height, 0)
    },
    visibleItems() {
      const start = Math.max(0, this.scrollTop - OVERSCAN * ITEM_HEIGHT)
      const end = this.scrollTop + this.containerHeight + OVERSCAN * ITEM_HEIGHT
      return this.virtualItems.filter(i => i.top + i.height >= start && i.top <= end)
    },
  },
  methods: {
    fmtTime,
    async loadRange() {
      if (this.loading) return
      this.loading = true
      const now = new Date()
      const start = new Date(now.getFullYear(), now.getMonth() - 1, 1)
      const end = new Date(now.getFullYear(), now.getMonth() + 2, 0)
      const fromStr = `${start.getFullYear()}-${pad(start.getMonth() + 1)}-${pad(start.getDate())}`
      const toStr = `${end.getFullYear()}-${pad(end.getMonth() + 1)}-${pad(end.getDate())}`
      this._loadedRange = { start: fromStr, end: toStr }
      try {
        const res = await api.listEvents(0, 500, fromStr, toStr)
        const items = Array.isArray(res) ? res : (res.items || [])
        this.events = items
      } catch (e) { this.events = [] }
      this.loading = false
      this.$nextTick(() => this.scrollToInitial())
    },
    scrollToInitial() {
      if (!this.$refs.listRef) return
      const now = new Date()
      const todayStr = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`
      // Find ongoing event
      let targetTop = -1
      for (const item of this.virtualItems) {
        if (item.type === 'header') continue
        const e = this.events.find(x => x.uid === item.uid)
        if (!e) continue
        const st = icalDateToObj(e.dtstart)
        const et = icalDateToObj(e.dtend)
        if (st && et && now >= st && now <= et) {
          targetTop = item.top
          break
        }
      }
      if (targetTop < 0) {
        // Position by time-of-day ratio within today
        const todaySec = (now.getHours() * 60 + now.getMinutes()) * 60
        const dayRatio = todaySec / 86400
        const total = this.totalHeight
        targetTop = Math.max(0, total * dayRatio - this.containerHeight / 2)
      }
      if (targetTop > 0) {
        this.$refs.listRef.scrollTop = Math.max(0, targetTop - 100)
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
      // Future: load more months when near edge
    },
    selectEvent(uid) {
      if (this.selectedUid === uid) {
        this.selectedUid = ''
        this.selectedEvent = null
        return
      }
      this.selectedUid = uid
      this.selectedEvent = this.events.find(e => e.uid === uid) || null
    },
    exportSingle() {
      if (!this.selectedEvent) return
      const e = this.selectedEvent
      const text = `${fmtTime(e.dtstart)} - ${fmtTime(e.dtend)}  ${e.summary || ''}`
      navigator.clipboard.writeText(text).then(() => alert('已复制')).catch(() => {})
    },
    async deleteSingle() {
      if (!this.selectedEvent || !confirm('确认删除此日程？')) return
      try {
        await api.deleteEvent(this.selectedEvent.uid)
        this.events = this.events.filter(e => e.uid !== this.selectedEvent.uid)
        this.selectedUid = ''
        this.selectedEvent = null
      } catch (e) { alert('删除失败') }
    },
  },
}
</script>

<style scoped>
.schedule-layout { display: flex; gap: 16px; height: 100%; }
.schedule-list { flex: 1; overflow-y: auto; position: relative; background: #fff; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,.06); }
.vl-total { position: relative; }
.vl-row { position: absolute; left: 0; right: 0; will-change: transform; }
.vl-date-header { display: flex; align-items: center; gap: 8px; padding: 8px 16px; background: #fafafa; border-bottom: 1px solid #f0f0f0; }
.dh-date { font-size: 14px; font-weight: 600; color: #333; }
.dh-lunar { font-size: 12px; color: #999; }
.vl-event { display: flex; gap: 12px; padding: 10px 16px; cursor: pointer; border-bottom: 1px solid #f5f5f5; transition: background .1s; }
.vl-event:hover { background: #fafafa; }
.vl-event.vl-selected { background: #e6f4ff; }
.ev-time { font-size: 13px; color: #888; min-width: 72px; padding-top: 2px; flex-shrink: 0; }
.ev-body { flex: 1; min-width: 0; }
.ev-title { font-size: 14px; font-weight: 500; color: #000; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.ev-range { font-size: 12px; color: #999; margin-top: 2px; }
.vl-loading { padding: 16px; text-align: center; color: #999; font-size: 13px; }

/* Right panel */
.schedule-detail { width: 320px; flex-shrink: 0; background: #fff; border-radius: 8px; padding: 20px; box-shadow: 0 1px 4px rgba(0,0,0,.06); }
.schedule-detail.empty { display: flex; align-items: center; justify-content: center; color: #999; font-size: 14px; }
.schedule-detail h3 { margin: 0 0 16px; font-size: 16px; }
.sd-row { display: flex; gap: 8px; margin-bottom: 10px; font-size: 14px; }
.sd-row label { color: #888; min-width: 48px; flex-shrink: 0; }
.sd-actions { display: flex; gap: 8px; margin-top: 20px; padding-top: 16px; border-top: 1px solid #f0f0f0; }
.sd-actions .btn-sm { padding: 6px 16px; border-radius: 6px; font-size: 13px; text-decoration: none; border: 1px solid #d9d9d9; background: #fff; cursor: pointer; }
.btn-danger { color: #cf1322; border-color: #ffa39e; }
</style>
