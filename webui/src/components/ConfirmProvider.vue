<template>
  <ModalConfirm
    :visible="state.visible"
    :title="state.title"
    :message="state.message"
    :type="state.type"
    :confirm-text="state.confirmText"
    :cancel-text="state.cancelText"
    :extra-text="state.extraText"
    :show-cancel="state.showCancel"
    @confirm="resolveConfirm('confirm')"
    @cancel="resolveConfirm('cancel')"
    @extra="resolveConfirm('extra')"
    @update:visible="v => { if (!v) resolveConfirm(null) }"
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
