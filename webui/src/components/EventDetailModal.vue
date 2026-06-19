<template>
  <transition name="modal">
    <div v-if="event" class="detail-overlay glass" @click.self="$emit('close')">
      <div class="detail-box no-transition">
        <div class="detail-header">
          <div class="dh-top">
            <h2>{{ event.summary || '(无标题)' }}</h2>
            <button class="close-btn" @click="$emit('close')"><X :size="20" /></button>
          </div>
          <div class="detail-meta">
            <span class="meta-tag"><Tag :size="12" /> {{ event.categories || '默认' }}</span>
          </div>
        </div>
        <div class="detail-body">
          <div class="detail-row">
            <Clock :size="20" class="detail-icon" />
            <div class="row-content">
              <div class="time-range">{{ formatTime(event.dtstart) }} - {{ formatTime(event.dtend) }}</div>
              <div class="date-val">{{ formatDateFull(event.dtstart) }}</div>
            </div>
          </div>
          <div v-if="event.location" class="detail-row">
            <MapPin :size="20" class="detail-icon" />
            <div class="row-val">{{ event.location }}</div>
          </div>
          <div v-if="event.description" class="detail-row">
            <FileText :size="20" class="detail-icon" />
            <div class="row-val desc-text">{{ event.description }}</div>
          </div>
          <div v-if="event.attachments && event.attachments.length" class="detail-row">
            <File :size="20" class="detail-icon" />
            <div class="row-content">
              <div v-for="(a, idx) in event.attachments" :key="idx" class="attachment-row">
                <span class="file-name">{{ a.name }}</span>
                <a :href="a.url" :download="a.name" class="btn-action btn-download" style="padding: 4px 8px;">下载</a>
              </div>
            </div>
          </div>
        </div>
        <div class="detail-footer">
          <button class="btn-action" @click="$emit('export', event)"><Share2 :size="14" /> 导出</button>
          <button class="btn-action" @click="handleEditClick"><Pencil :size="14" /> 编辑</button>
          <button class="btn-action btn-danger" @click="$emit('delete', event)"><Trash2 :size="14" /> 删除</button>
        </div>
      </div>
    </div>
  </transition>
</template>

<script>
import { X, Tag, Clock, MapPin, FileText, File, Share2, Pencil, Trash2 } from 'lucide-vue-next'
import { icalDateToObj, formatTime, formatDateFull } from '../utils/ical.js'

export default {
  components: { X, Tag, Clock, MapPin, FileText, File, Share2, Pencil, Trash2 },
  props: ['event'],
  emits: ['close', 'edit', 'delete', 'export'],
  methods: {
    formatTime(s) { return formatTime(s) },
    formatDateFull(s) { return formatDateFull(s) },
    handleEditClick() {
      console.log('DetailModal: Edit button clicked, event:', this.event);
      if (!this.event || !this.event.uid) {
        console.error('DetailModal: Event UID missing!');
        return;
      }
      this.$emit('edit', this.event);
    }
  }
}
</script>

<style>
.detail-overlay { position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.4); display:flex; align-items:center; justify-content:center; z-index:2000; backdrop-filter:blur(8px); }
.detail-box { background:white; border-radius:var(--radius-xl); width:100%; max-width:500px; max-height:90vh; overflow-y:auto; box-shadow:var(--shadow-xl); border:1px solid var(--glass-border); position:relative; padding:32px; }
.close-btn { background:transparent; border:none; padding:4px; color:var(--text-tertiary); cursor:pointer; transition:.2s cubic-bezier(0.4,0,0.2,1); display:flex; position:absolute; top:20px; right:20px; z-index:10; }
.close-btn:hover { color:var(--text-primary); transform:rotate(90deg); }
.detail-header h2 { margin:0; font-size:22px; color:var(--text-primary); line-height:1.3; padding-right:32px; }
.detail-meta { margin-top:12px; }
.meta-tag { display:inline-flex; align-items:center; gap:6px; padding:4px 12px; background:var(--bg-hover); border-radius:20px; font-size:12px; color:var(--text-secondary); font-weight:500; }
.detail-body { margin-top:32px; display:flex; flex-direction:column; gap:28px; }
.detail-row { display:flex; gap:20px; }
.detail-icon { color:var(--brand); flex-shrink:0; margin-top:2px; opacity:0.8; }
.row-content { flex:1; }
.time-range { font-weight:700; font-size:18px; color:var(--text-primary); }
.date-val { color:var(--text-secondary); font-size:14px; margin-top:2px; font-weight:500; }
.row-val { font-size:15px; color:var(--text-primary); line-height:1.5; }
.desc-text { white-space:pre-wrap; word-break:break-all; color:var(--text-secondary); }
.detail-footer { margin-top:48px; border-top:1px solid var(--border-base); padding-top:24px; display:flex; flex-wrap:wrap; gap:10px; }
.btn-action { display:flex; align-items:center; gap:8px; padding:8px 16px; border-radius:var(--radius-sm); border:1px solid var(--border-strong); background:white; cursor:pointer; font-size:13px; font-weight:500; transition:all .2s; color:var(--text-secondary); text-decoration:none; }
.btn-action:hover { border-color:var(--brand); color:var(--brand); background:var(--bg-info); }
.btn-danger { color:var(--danger); border-color:var(--danger-border); }
.btn-danger:hover { background:var(--bg-danger); border-color:var(--danger); }
.attachment-row { display:flex; align-items:center; justify-content:space-between; gap:12px; padding:6px 0; }
.file-name { font-size:13px; color:var(--text-primary); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
</style>
