<template>
  <div class="skeleton" :class="['skeleton-' + variant]" :style="style">
    <div class="skeleton-pulse"></div>
  </div>
</template>

<script>
export default {
  props: {
    variant: { type: String, default: 'text' },
    width: { type: String, default: '' },
    height: { type: String, default: '' },
  },
  computed: {
    style() {
      const s = {}
      if (this.width) s.width = this.width
      if (this.height) s.height = this.height
      return s
    }
  }
}
</script>

<style scoped>
.skeleton {
  position: relative;
  overflow: hidden;
  background: var(--bg-hover);
  border-radius: var(--radius-sm);
}
.skeleton-text { height: 14px; margin-bottom: 8px; }
.skeleton-title { height: 20px; width: 60%; margin-bottom: 12px; }
.skeleton-avatar { width: 44px; height: 44px; border-radius: 50%; flex-shrink: 0; }
.skeleton-card { height: 120px; border-radius: var(--radius-md); }
.skeleton-row { height: 52px; margin-bottom: 4px; border-radius: var(--radius-sm); }

.skeleton-pulse {
  position: absolute;
  inset: 0;
  background: linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent);
  animation: shimmer 1.5s ease-in-out infinite;
}
@keyframes shimmer {
  0% { transform: translateX(-100%); }
  100% { transform: translateX(100%); }
}
</style>
