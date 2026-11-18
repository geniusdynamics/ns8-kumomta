<!--
  Copyright (C) 2023 Nethesis S.r.l.
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <div class="app-side-menu-content">
    <div class="instance-name">
      <div v-if="instanceLabel">{{ instanceLabel }}</div>
      <div v-else-if="instanceName">{{ instanceName }}</div>
      <cv-skeleton-text
        v-else
        :width="instanceNameSkeletonWidth"
      ></cv-skeleton-text>
    </div>

    <cv-side-nav-items>
      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'status')"
        :class="{ 'current-page': isLinkActive('status') }"
      >
        <template v-slot:nav-icon><Activity20 /></template>
        <span>{{ $t("status.title") }}</span>
      </cv-side-nav-link>
      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'queue')"
        :class="{ 'current-page': isLinkActive('queue') }"
      >
        <template v-slot:nav-icon><Email20 /></template>
        <span>{{ $t("queue.title") }}</span>
      </cv-side-nav-link>
      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'settings')"
        :class="{ 'current-page': isLinkActive('settings') }"
      >
        <template v-slot:nav-icon><Settings20 /></template>
        <span>{{ $t("settings.title") }}</span>
      </cv-side-nav-link>
      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'users')"
        :class="{ 'current-page': isLinkActive('users') }"
      >
        <template v-slot:nav-icon><UserMultiple20 /></template>
        <span>{{ $t("users.title") }}</span>
      </cv-side-nav-link>
      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'domains')"
        :class="{ 'current-page': isLinkActive('domains') }"
      >
        <template v-slot:nav-icon><Certificate20 /></template>
        <span>{{ $t("domains.title") }}</span>
      </cv-side-nav-link>
      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'delivery')"
        :class="{ 'current-page': isLinkActive('delivery') }"
      >
        <template v-slot:nav-icon><DeliveryTruck20 /></template>
        <span>{{ $t("delivery.title") }}</span>
      </cv-side-nav-link>
      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'integrations')"
        :class="{ 'current-page': isLinkActive('integrations') }"
      >
        <template v-slot:nav-icon><Api20 /></template>
        <span>{{ $t("integrations.title") }}</span>
      </cv-side-nav-link>
      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'openbao')"
        :class="{ 'current-page': isLinkActive('openbao') }"
      >
        <template v-slot:nav-icon><Locked20 /></template>
        <span>{{ $t("openbao.title") }}</span>
      </cv-side-nav-link>
      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'sending-ips')"
        :class="{ 'current-page': isLinkActive('sending-ips') }"
      >
        <template v-slot:nav-icon><Gauge20 /></template>
        <span>{{ $t("sending_ips.title") }}</span>
      </cv-side-nav-link>
      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'cluster')"
        :class="{ 'current-page': isLinkActive('cluster') }"
      >
        <template v-slot:nav-icon><Network20 /></template>
        <span>{{ $t("cluster.title") }}</span>
      </cv-side-nav-link>
      <cv-side-nav-link
        @click="goToAppPage(instanceName, 'about')"
        :class="{ 'current-page': isLinkActive('about') }"
      >
        <template v-slot:nav-icon><Information20 /></template>
        <span>{{ $t("about.title") }}</span>
      </cv-side-nav-link>
    </cv-side-nav-items>
  </div>
</template>

<script>
import Settings20 from "@carbon/icons-vue/es/settings/20";
import Information20 from "@carbon/icons-vue/es/information/20";
import Activity20 from "@carbon/icons-vue/es/activity/20";
import Email20 from "@carbon/icons-vue/es/email/20";
import UserMultiple20 from "@carbon/icons-vue/es/user--multiple/20";
import Certificate20 from "@carbon/icons-vue/es/certificate/20";
import DeliveryTruck20 from "@carbon/icons-vue/es/delivery-truck/20";
import Locked20 from "@carbon/icons-vue/es/locked/20";
import Api20 from "@carbon/icons-vue/es/api/20";
import Network20 from "@carbon/icons-vue/es/network--3/20";
import Gauge20 from "@carbon/icons-vue/es/meter/20";
import { mapState } from "vuex";
import { QueryParamService, UtilService } from "@nethserver/ns8-ui-lib";

export default {
  name: "AppSideMenuContent",
  components: {
    Settings20,
    Information20,
    Activity20,
    Email20,
    UserMultiple20,
    Certificate20,
    DeliveryTruck20,
    Locked20,
    Api20,
    Network20,
    Gauge20,
  },
  mixins: [QueryParamService, UtilService],
  data() {
    return {
      instanceNameSkeletonWidth: "70%",
    };
  },
  computed: {
    ...mapState(["instanceName", "instanceLabel", "core"]),
  },
  created() {
    // register to appNavigation event
    this.$root.$on("appNavigation", this.onAppNavigation);
  },
  beforeDestroy() {
    // remove event listener
    this.$root.$off("appNavigation");
  },
  methods: {
    isLinkActive(page) {
      return this.getPage() === page;
    },
    onAppNavigation() {
      // highlight current page in side menu
      this.$forceUpdate();
    },
  },
};
</script>

<style scoped lang="scss">
.instance-name span {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
