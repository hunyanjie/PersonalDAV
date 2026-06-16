<template>
  <transition name="modal">
    <div v-if="visible" class="modal-overlay" @click.self="$emit('close')">
      <div class="modal-card glass no-transition">
        <slot></slot>
      </div>
    </div>
  </transition>
</template>

<script>
export default {
  props: ['visible'],
  emits: ['close']
}
</script>

<style scoped>
.modal-overlay { position: fixed; inset: 0; z-index: 3000; background: rgba(0,0,0,0.6); display: flex; align-items: center; justify-content: center; backdrop-filter: blur(8px); }
.modal-card { background: white; border-radius: var(--radius-xl); width: 100%; max-width: 600px; max-height: 90vh; box-shadow: var(--shadow-xl); overflow: hidden; border: 1px solid var(--glass-border); position: relative; }
.modal-enter-active, .modal-leave-active { transition: all 0.3s ease; }
.modal-enter-from, .modal-leave-to { opacity: 0; transform: scale(0.95); }
</style>
