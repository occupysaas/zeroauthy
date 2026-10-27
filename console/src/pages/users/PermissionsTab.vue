<script setup lang="ts">
import type { SystemTenant, User } from '../../api/client'
import PermissionAssignments from '../roles/PermissionAssignments.vue'
defineProps<{ tenant: SystemTenant; user: User }>()
</script>
<template><PermissionAssignments :tenant="tenant" kind="users" :id="user.user_id ?? ''" /></template>
