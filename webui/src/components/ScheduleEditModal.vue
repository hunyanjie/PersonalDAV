<template>
  <transition name="modal">
    <div v-if="visible" class="modal-overlay" @click.self="$emit('close')">
      <div class="modal-card glass">
        <div class="modal-header">
          <h3>{{ eventId ? '编辑日程' : '新建日程' }}</h3>
          <button class="btn-close-circle" @click="$emit('close')"><X :size="20" /></button>
        </div>
        <div class="modal-body-scroll">
          <CalendarEventEdit 
            :eventId="eventId" 
            :isModal="true"
            :visible="visible"
            @save="$emit('save')"
            @close="$emit('close')"
          />
        </div>
      </div>
    </div>
  </transition>
</template>

<script>
import { X } from 'lucide-vue-next'
import CalendarEventEdit from '../views/CalendarEventEdit.vue'
export default {
  components: { CalendarEventEdit, X },
  props: ['visible', 'eventId'],
  emits: ['close', 'save'],
  watch: {
    visible(val) {
      if (val) console.log('ScheduleEditModal: visible, eventId:', this.eventId);
    }
  }
}
</script>

<style scoped>
.modal-overlay { position: fixed; inset: 0; z-index: 4000; background: rgba(0,0,0,0.4); display: flex; align-items: center; justify-content: center; backdrop-filter: blur(8px); }
.modal-card { background: white; border-radius: var(--radius-xl); width: 90vw; max-width: 680px; max-height: 90vh; display: flex; flex-direction: column; box-shadow: var(--shadow-xl); border: 1px solid var(--glass-border); overflow: hidden; }
.modal-header { padding: 20px 24px; border-bottom: 1px solid var(--border-base); display: flex; justify-content: space-between; align-items: center; background: #fafafa; flex-shrink: 0; }
.modal-body-scroll { flex: 1; overflow-y: auto; }
.btn-close-circle { border: none; background: transparent; cursor: pointer; color: var(--text-tertiary); display: flex; transition: .2s; }
.btn-close-circle:hover { color: var(--text-primary); transform: rotate(90deg); }
</style>
