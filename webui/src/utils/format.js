export function pad(n) {
  return String(n).padStart(2, '0')
}

export function formatSize(sizeVal) {
  try {
    let size = parseFloat(sizeVal)
    if (isNaN(size)) return String(sizeVal)
    for (const unit of ['B', 'KB', 'MB', 'GB', 'TB']) {
      if (size < 1024) return `${size.toFixed(1)} ${unit}`
      size /= 1024
    }
    return `${size.toFixed(1)} PB`
  } catch {
    return String(sizeVal)
  }
}