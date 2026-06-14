<template>
  <router-view />
  <Toast />
  <ConfirmProvider />
</template>

<script>
import Toast from './components/Toast.vue'
import ConfirmProvider from './components/ConfirmProvider.vue'
export default {
  components: { Toast, ConfirmProvider },
}
</script>
