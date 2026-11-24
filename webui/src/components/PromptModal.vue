<template>
  <transition name="modal">
    <div v-if="visible" class="modal-overlay" @click.self="$emit('cancel')">
      <div class="modal-card glass">
        <h3>{{ title }}</h3>
        <p>{{ message }}</p>
        <input v-model="localValue" :placeholder="placeholder" @keyup.enter="$emit('confirm', localValue)" autofocus />
        <div class="modal-actions">
          <button class="btn-sm" @click="$emit('cancel')">{{ cancelText }}</button>
          <button class="btn-sm btn-primary" @click="$emit('confirm', localValue)">{{ confirmText }}</button>
        </div>
      </div>
    </div>
  </transition>
</template>

<script>
export default {
  props: {
    visible: Boolean,
    title: String,
    message: String,
    initialValue: String,
    placeholder: String,
    confirmText: { type: String, default: '确定' },
    cancelText: { type: String, default: '取消' }
  },
  data: () => ({ localValue: '' }),
  watch: {
    visible(v) { if (v) this.localValue = this.initialValue }
  }
}
</script>

<style scoped>
.modal-overlay { position: fixed; inset: 0; background: #0009; display: flex; align-items: center; justify-content: center; z-index: 5000; backdrop-filter: blur(8px); }
.modal-card { background: var(--bg-card); width: 90vw; max-width: 400px; border-radius: var(--radius-lg); padding: 24px; box-shadow: var(--shadow-xl); }
.modal-card h3 { margin: 0 0 16px; font-size: 16px; }
.modal-card input { width: 100%; padding: 10px 14px; border: 1px solid var(--border-input); border-radius: var(--radius-sm); font-size: 14px; box-sizing: border-box; outline: none; margin-bottom: 16px; }
.modal-card input:focus { border-color: var(--brand); box-shadow: 0 0 0 3px var(--brand-ring); }
.modal-actions { display: flex; justify-content: flex-end; gap: 12px; }
.btn-sm { padding: 8px 16px; border: 1px solid var(--border-base); border-radius: var(--radius-md); cursor: pointer; }
.btn-primary { background: var(--brand); color: white; border: none; }
</style>
