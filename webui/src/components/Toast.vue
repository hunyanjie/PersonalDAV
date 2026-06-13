<template>
  <div class="toast-container">
    <transition-group name="toast">
      <div v-for="t in toasts" :key="t.id" class="toast" :class="'toast-' + t.type" @click="dismissToast(t.id)">
        <component :is="iconMap[t.type]" :size="18" class="toast-icon" />
        <span class="toast-msg">{{ t.message }}</span>
      </div>
    </transition-group>
  </div>
</template>

<script>
import { CheckCircle, AlertTriangle, AlertCircle, Info, X } from 'lucide-vue-next'
import { useToast } from '../utils/toast.js'
export default {
  components: { CheckCircle, AlertTriangle, AlertCircle, Info, X },
  setup() {
    return useToast()
  },
  computed: {
    iconMap() {
      return {
        success: 'CheckCircle',
        warning: 'AlertTriangle',
        error: 'AlertCircle',
        info: 'Info',
      }
    }
  }
}
</script>

<style scoped>
.toast-container {
  position: fixed;
  top: 20px;
  right: 20px;
  z-index: 10000;
  display: flex;
  flex-direction: column;
  gap: 8px;
  pointer-events: none;
}
.toast {
  pointer-events: auto;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 14px 20px;
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-lg);
  cursor: pointer;
  font-size: 14px;
  font-weight: 500;
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border: 1px solid rgba(255,255,255,0.3);
  max-width: 380px;
}
.toast-success { background: rgba(240, 255, 240, 0.9); color: #1a7a1a; border-color: #b7eb8f; }
.toast-error { background: rgba(255, 240, 240, 0.9); color: #cf1322; border-color: #ffa39e; }
.toast-warning { background: rgba(255, 250, 230, 0.9); color: #ad6800; border-color: #ffe58f; }
.toast-info { background: rgba(230, 244, 255, 0.9); color: var(--brand); border-color: var(--brand-ring); }

.toast-enter-active { transition: all 0.3s cubic-bezier(0.34, 1.56, 0.64, 1); }
.toast-leave-active { transition: all 0.25s ease; }
.toast-enter-from { opacity: 0; transform: translateX(100%) scale(0.9); }
.toast-leave-to { opacity: 0; transform: translateX(100%); }
</style>
