<template>
  <ModalConfirm
    :visible="state.visible"
    :title="state.title"
    :message="state.message"
    :type="state.type"
    :confirm-text="state.confirmText"
    :cancel-text="state.cancelText"
    @confirm="resolveConfirm(true)"
    @cancel="resolveConfirm(false)"
    @update:visible="v => { if (!v) resolveConfirm(false) }"
  />
</template>

<script>
import ModalConfirm from './ModalConfirm.vue'
import { useConfirm } from '../utils/confirm.js'
export default {
  components: { ModalConfirm },
  setup() { return useConfirm() },
}
</script>
