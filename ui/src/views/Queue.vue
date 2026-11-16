<!--
  Copyright (C) 2026 Genius Dynamics
  SPDX-License-Identifier: GPL-3.0-or-later
-->
<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title title-with-action">
        <h2>{{ $t("queue.title") }}</h2>
        <NsButton
          kind="ghost"
          :icon="Restart20"
          :loading="loading.status || loading.events"
          :disabled="loading.status || loading.events"
          @click="refresh"
          >{{ $t("queue.refresh") }}</NsButton
        >
      </cv-column>
    </cv-row>
    <cv-row v-if="error.status">
      <cv-column>
        <NsInlineNotification
          kind="error"
          :title="$t('action.get-queue-status')"
          :description="error.status"
          :showCloseButton="false"
        />
      </cv-column>
    </cv-row>
    <cv-row v-if="!loading.status && !running">
      <cv-column>
        <NsInlineNotification
          kind="warning"
          :title="$t('queue.not_running')"
          :description="$t('queue.not_running_description')"
          :showCloseButton="false"
        />
      </cv-column>
    </cv-row>
    <!-- totals -->
    <cv-row>
      <cv-column v-for="key in totalKeys" :key="key" :md="2" :lg="2" :max="2">
        <NsInfoCard
          light
          :title="String(totals[key] !== undefined ? totals[key] : '-')"
          :description="$t('queue.total_' + key)"
          :loading="loading.status"
          class="min-height-card"
        />
      </cv-column>
    </cv-row>
    <!-- scheduled queues -->
    <cv-row>
      <cv-column :lg="8">
        <cv-tile light>
          <h4 class="mg-bottom">{{ $t("queue.top_destinations") }}</h4>
          <cv-skeleton-text
            v-if="loading.status"
            :paragraph="true"
            :line-count="4"
          />
          <NsEmptyState
            v-else-if="!queues.length"
            :title="$t('queue.no_queued')"
          />
          <cv-structured-list v-else>
            <template slot="headings">
              <cv-structured-list-heading>{{
                $t("queue.domain")
              }}</cv-structured-list-heading>
              <cv-structured-list-heading>{{
                $t("queue.scheduled")
              }}</cv-structured-list-heading>
            </template>
            <template slot="items">
              <cv-structured-list-item v-for="q in queues" :key="q.domain">
                <cv-structured-list-data class="break-word">{{
                  q.domain
                }}</cv-structured-list-data>
                <cv-structured-list-data>{{
                  q.scheduled
                }}</cv-structured-list-data>
              </cv-structured-list-item>
            </template>
          </cv-structured-list>
        </cv-tile>
      </cv-column>
      <cv-column :lg="8">
        <cv-tile light>
          <h4 class="mg-bottom">{{ $t("queue.delivery_stats") }}</h4>
          <cv-skeleton-text
            v-if="loading.status"
            :paragraph="true"
            :line-count="4"
          />
          <NsEmptyState
            v-else-if="!providers.length"
            :title="$t('queue.no_stats')"
          />
          <cv-structured-list v-else>
            <template slot="headings">
              <cv-structured-list-heading>{{
                $t("queue.provider")
              }}</cv-structured-list-heading>
              <cv-structured-list-heading>{{
                $t("queue.delivered")
              }}</cv-structured-list-heading>
              <cv-structured-list-heading>{{
                $t("queue.deferred")
              }}</cv-structured-list-heading>
              <cv-structured-list-heading>{{
                $t("queue.bounced")
              }}</cv-structured-list-heading>
              <cv-structured-list-heading>{{
                $t("queue.queued")
              }}</cv-structured-list-heading>
            </template>
            <template slot="items">
              <cv-structured-list-item v-for="p in providers" :key="p.provider">
                <cv-structured-list-data class="break-word">{{
                  p.provider
                }}</cv-structured-list-data>
                <cv-structured-list-data>{{
                  p.delivered
                }}</cv-structured-list-data>
                <cv-structured-list-data>{{
                  p.deferred
                }}</cv-structured-list-data>
                <cv-structured-list-data>{{
                  p.bounced
                }}</cv-structured-list-data>
                <cv-structured-list-data>{{
                  p.queued
                }}</cv-structured-list-data>
              </cv-structured-list-item>
            </template>
          </cv-structured-list>
        </cv-tile>
      </cv-column>
    </cv-row>
    <!-- recent events -->
    <cv-row>
      <cv-column>
        <cv-tile light>
          <h4 class="mg-bottom">{{ $t("queue.recent_events") }}</h4>
          <p class="mg-bottom helper">{{ $t("queue.recent_events_helper") }}</p>
          <NsInlineNotification
            v-if="error.events"
            kind="error"
            :title="$t('action.list-recent-events')"
            :description="error.events"
            :showCloseButton="false"
          />
          <cv-skeleton-text
            v-if="loading.events"
            :paragraph="true"
            :line-count="5"
          />
          <NsEmptyState
            v-else-if="!events.length"
            :title="$t('queue.no_events')"
          />
          <cv-structured-list v-else>
            <template slot="headings">
              <cv-structured-list-heading>{{
                $t("queue.time")
              }}</cv-structured-list-heading>
              <cv-structured-list-heading>{{
                $t("queue.type")
              }}</cv-structured-list-heading>
              <cv-structured-list-heading>{{
                $t("queue.recipient")
              }}</cv-structured-list-heading>
              <cv-structured-list-heading>{{
                $t("queue.response")
              }}</cv-structured-list-heading>
            </template>
            <template slot="items">
              <cv-structured-list-item
                v-for="(ev, index) in events"
                :key="index"
              >
                <cv-structured-list-data>{{
                  formatTime(ev.time)
                }}</cv-structured-list-data>
                <cv-structured-list-data>
                  <NsTag :kind="tagKind(ev.type)" :label="ev.type" />
                </cv-structured-list-data>
                <cv-structured-list-data class="break-word">{{
                  ev.recipient
                }}</cv-structured-list-data>
                <cv-structured-list-data class="break-word"
                  >{{ ev.code }} {{ ev.response }}</cv-structured-list-data
                >
              </cv-structured-list-item>
            </template>
          </cv-structured-list>
        </cv-tile>
      </cv-column>
    </cv-row>
  </cv-grid>
</template>

<script>
import { mapState } from "vuex";
import {
  QueryParamService,
  UtilService,
  TaskService,
  IconService,
  PageTitleService,
} from "@nethserver/ns8-ui-lib";
import ModuleTask from "@/mixins/moduleTask";

export default {
  name: "Queue",
  mixins: [
    TaskService,
    IconService,
    UtilService,
    QueryParamService,
    PageTitleService,
    ModuleTask,
  ],
  pageTitle() {
    return this.$t("queue.title") + " - " + this.appName;
  },
  data() {
    return {
      q: { page: "queue" },
      urlCheckInterval: null,
      running: true,
      totals: {},
      totalKeys: [
        "scheduled",
        "received",
        "delivered",
        "deferred",
        "bounced",
        "rejected",
      ],
      queues: [],
      providers: [],
      events: [],
      loading: { status: false, events: false },
      error: { status: "", events: "" },
    };
  },
  computed: {
    ...mapState(["instanceName", "core", "appName"]),
  },
  created() {
    this.refresh();
  },
  beforeRouteEnter(to, from, next) {
    next((vm) => {
      vm.watchQueryData(vm);
      vm.urlCheckInterval = vm.initUrlBindingForApp(vm, vm.q.page);
    });
  },
  beforeRouteLeave(to, from, next) {
    clearInterval(this.urlCheckInterval);
    next();
  },
  methods: {
    refresh() {
      this.getQueueStatus();
      this.listRecentEvents();
    },
    async getQueueStatus() {
      this.loading.status = true;
      this.error.status = "";
      try {
        const out = await this.runModuleTask("get-queue-status");
        this.running = out.running;
        this.totals = out.totals;
        this.queues = out.queues;
        this.providers = out.providers;
      } catch (failure) {
        this.error.status = this.taskErrorMessage(failure);
      }
      this.loading.status = false;
    },
    async listRecentEvents() {
      this.loading.events = true;
      this.error.events = "";
      try {
        const out = await this.runModuleTask("list-recent-events", {
          limit: 100,
        });
        this.events = out.events;
      } catch (failure) {
        this.error.events = this.taskErrorMessage(failure);
      }
      this.loading.events = false;
    },
    formatTime(epoch) {
      return epoch ? new Date(epoch * 1000).toLocaleString() : "-";
    },
    tagKind(type) {
      if (type === "Delivery") {
        return "green";
      }
      if (type === "TransientFailure") {
        return "warm-gray";
      }
      return "red";
    },
  },
};
</script>

<style scoped lang="scss">
@import "../styles/carbon-utils";
.mg-bottom {
  margin-bottom: $spacing-06;
}
.title-with-action {
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.helper {
  font-size: 0.75rem;
}
</style>
