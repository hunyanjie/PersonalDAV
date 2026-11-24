import { reactive } from 'vue'

const state = reactive({ visible: false, title: '', message: '', initialValue: '', confirmText: '确定', cancelText: '取消' })
let _resolve = null

export function showPrompt({ title, message, initialValue, confirmText, cancelText } = {}) {
  state.visible = true
  state.title = title || '输入'
  state.message = message || ''
  state.initialValue = initialValue || ''
  state.confirmText = confirmText || '确定'
  state.cancelText = cancelText || '取消'
  return new Promise(resolve => { _resolve = resolve })
}

export function resolvePrompt(result) {
  if (_resolve) _resolve(result)
  _resolve = null
  state.visible = false
}

export function usePrompt() {
  return { state, showPrompt, resolvePrompt }
}
