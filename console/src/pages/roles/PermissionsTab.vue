<script setup lang="ts">
import type { SystemTenant } from '../../api/client'
import PermissionAssignments from './PermissionAssignments.vue'
defineProps<{ tenant: SystemTenant; roleId: string }>()
</script>
<template><PermissionAssignments :tenant="tenant" kind="roles" :id="roleId" /></template>
