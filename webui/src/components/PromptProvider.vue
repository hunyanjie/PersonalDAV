<template>
  <PromptModal
    :visible="state.visible"
    :title="state.title"
    :message="state.message"
    :initial-value="state.initialValue"
    :confirm-text="state.confirmText"
    :cancel-text="state.cancelText"
    @confirm="v => resolvePrompt(v)"
    @cancel="resolvePrompt(null)"
  />
</template>

<script>
import PromptModal from './PromptModal.vue'
import { usePrompt } from '../utils/prompt.js'
export default {
  components: { PromptModal },
  setup() { return usePrompt() },
}
</script>
