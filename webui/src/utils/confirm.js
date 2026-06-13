const state = { visible: false, title: '', message: '', type: 'info', confirmText: '确定', cancelText: '取消' }
let _resolve = null

export function showConfirm({ title, message, type, confirmText, cancelText } = {}) {
  state.visible = true
  state.title = title || '确认'
  state.message = message || ''
  state.type = type || 'info'
  state.confirmText = confirmText || '确定'
  state.cancelText = cancelText || '取消'
  return new Promise(resolve => { _resolve = resolve })
}

export function resolveConfirm(result) {
  if (_resolve) _resolve(result)
  _resolve = null
  state.visible = false
}

export function useConfirm() {
  return { state, showConfirm, resolveConfirm }
}
