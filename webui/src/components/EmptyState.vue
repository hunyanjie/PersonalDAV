<template>
  <div class="empty-state">
    <svg class="empty-svg" viewBox="0 0 120 120" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="60" cy="48" r="20" stroke="currentColor" stroke-width="2" stroke-dasharray="4 3" fill="none" opacity="0.3" />
      <path d="M40 88 L40 76 Q40 68 48 68 L72 68 Q80 68 80 76 L80 88" stroke="currentColor" stroke-width="2" fill="none" opacity="0.2" />
      <path d="M52 48 Q52 40 60 40 Q68 40 68 48 Q68 56 60 56 Q52 56 52 48Z" stroke="currentColor" stroke-width="1.5" fill="none" opacity="0.15" />
      <path d="M30 90 L90 90" stroke="currentColor" stroke-width="1.5" stroke-dasharray="4 4" opacity="0.15" />
      <circle cx="60" cy="48" r="28" stroke="currentColor" stroke-width="1" stroke-dasharray="2 4" fill="none" opacity="0.1" />
    </svg>
    <h3 class="empty-title">{{ title }}</h3>
    <p class="empty-desc" v-if="description">{{ description }}</p>
    <slot name="action">
      <button v-if="actionText" class="btn-empty" @click="$emit('action')">
        <component :is="actionIcon" :size="16" v-if="actionIcon" />
        {{ actionText }}
      </button>
    </slot>
  </div>
</template>

<script>
import { Plus } from 'lucide-vue-next'
export default {
  props: {
    title: { type: String, default: '暂无数据' },
    description: { type: String, default: '' },
    actionText: { type: String, default: '' },
    actionIcon: { type: [Object, String], default: () => Plus },
  },
  emits: ['action'],
  components: { Plus },
}
</script>

<style scoped>
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 60px 20px;
  color: var(--text-tertiary);
}
.empty-svg { width: 100px; height: 100px; margin-bottom: 20px; }
.empty-title { margin: 0 0 8px; font-size: 16px; font-weight: 600; color: var(--text-secondary); }
.empty-desc { margin: 0 0 20px; font-size: 13px; color: var(--text-quaternary); text-align: center; max-width: 280px; }
.btn-empty {
  display: inline-flex; align-items: center; gap: 8px;
  padding: 10px 24px;
  background: var(--brand); color: white;
  border: none; border-radius: var(--radius-md);
  font-size: 14px; font-weight: 600; cursor: pointer;
  transition: all .2s;
}
.btn-empty:hover { background: var(--brand-hover); transform: translateY(-1px); }
</style>
