<template>
  <transition name="modal">
    <div v-if="visible" class="modal-overlay" @click.self="onCancel">
      <div class="modal-box glass">
        <div class="modal-header">
          <component :is="iconComp" :size="22" class="icon" :class="'icon-' + type" />
          <h3>{{ title }}</h3>
        </div>
        <div class="modal-body">
          <slot>{{ message }}</slot>
        </div>
        <div class="modal-footer">
          <button class="btn-sm" @click="onCancel">{{ cancelText }}</button>
          <button class="btn-sm" :class="'btn-' + type" @click="onConfirm" ref="confirmBtn">{{ confirmText }}</button>
        </div>
      </div>
    </div>
  </transition>
</template>

<script>
import { AlertTriangle, AlertCircle, Info, CheckCircle } from 'lucide-vue-next'
export default {
  props: {
    visible: Boolean,
    title: { type: String, default: '确认' },
    message: { type: String, default: '' },
    type: { type: String, default: 'info' },
    confirmText: { type: String, default: '确定' },
    cancelText: { type: String, default: '取消' },
  },
  emits: ['confirm', 'cancel', 'update:visible'],
  components: { AlertTriangle, AlertCircle, Info, CheckCircle },
  computed: {
    iconComp() {
      return {
        danger: 'AlertCircle',
        warning: 'AlertTriangle',
        success: 'CheckCircle',
        info: 'Info',
      }[this.type] || 'Info'
    }
  },
  watch: {
    visible(v) { if (v) this.$nextTick(() => this.$refs.confirmBtn?.focus()) }
  },
  methods: {
    onConfirm() { this.$emit('confirm'); this.close() },
    onCancel() { this.$emit('cancel'); this.close() },
    close() { this.$emit('update:visible', false) },
  },
}
</script>

<style scoped>
.modal-overlay {
  position: fixed; inset: 0;
  background: rgba(0,0,0,0.4);
  backdrop-filter: blur(4px);
  display: flex; align-items: center; justify-content: center;
  z-index: 9000;
}
.modal-box {
  background: var(--bg-card);
  border-radius: var(--radius-lg);
  padding: 32px;
  width: 400px;
  max-width: 90vw;
  box-shadow: var(--shadow-xl);
}
.modal-header {
  display: flex; align-items: center; gap: 12px;
  margin-bottom: 16px;
}
.icon { flex-shrink: 0; }
.icon-danger { color: var(--danger); }
.icon-warning { color: var(--warning); }
.icon-success { color: var(--success); }
.icon-info { color: var(--brand); }
.modal-header h3 { margin: 0; font-size: 18px; color: var(--text-primary); }
.modal-body { font-size: 14px; color: var(--text-secondary); line-height: 1.6; margin-bottom: 24px; }
.modal-footer { display: flex; justify-content: flex-end; gap: 12px; }
.btn-sm {
  padding: 10px 24px; border-radius: var(--radius-md);
  font-size: 14px; font-weight: 600; cursor: pointer;
  border: 1px solid var(--border-strong); background: white;
  transition: all .2s;
}
.btn-sm:hover { border-color: var(--border-input); }
.btn-danger { background: var(--danger); color: white; border-color: var(--danger); }
.btn-danger:hover { background: #ff7875; }
.btn-warning { background: var(--warning); color: white; border-color: var(--warning); }
.btn-success { background: var(--success); color: white; border-color: var(--success); }
.btn-info { background: var(--brand); color: white; border-color: var(--brand); }
.btn-info:hover { background: var(--brand-hover); }

.modal-enter-active, .modal-leave-active { transition: all 0.25s cubic-bezier(0.34, 1.56, 0.64, 1); }
.modal-enter-from, .modal-leave-to { opacity: 0; transform: scale(0.9) translateY(20px); }
</style>
