<template>
  <router-view />
  <Toast />
  <ConfirmProvider />
  <PromptProvider />
</template>

<script>
import Toast from './components/Toast.vue'
import ConfirmProvider from './components/ConfirmProvider.vue'
import PromptProvider from './components/PromptProvider.vue'
export default {
  components: { Toast, ConfirmProvider, PromptProvider },
}
</script>
