import { reactive } from 'vue'

const toasts = reactive([])
let _id = 0

export function showToast(message, type = 'info', duration = 3500) {
  const id = ++_id
  toasts.push({ id, message, type, duration })
  if (duration > 0) {
    setTimeout(() => dismissToast(id), duration)
  }
  return id
}

export function dismissToast(id) {
  const idx = toasts.findIndex(t => t.id === id)
  if (idx > -1) toasts.splice(idx, 1)
}

export function useToast() {
  return { toasts, showToast, dismissToast }
}
