//
// Copyright (C) 2023 Nethesis S.r.l.
// SPDX-License-Identifier: GPL-3.0-or-later
//
import Vue from "vue";
import VueRouter from "vue-router";
import Status from "../views/Status.vue";
import Settings from "../views/Settings.vue";
import Queue from "../views/Queue.vue";
import Users from "../views/Users.vue";
import Domains from "../views/Domains.vue";
import Delivery from "../views/Delivery.vue";
import OpenBao from "../views/OpenBao.vue";
import Integrations from "../views/Integrations.vue";

Vue.use(VueRouter);

const routes = [
  {
    path: "/",
    name: "Status",
    component: Status,
    alias: "/status", // important
  },
  {
    path: "/queue",
    name: "Queue",
    component: Queue,
  },
  {
    path: "/settings",
    name: "Settings",
    component: Settings,
  },
  {
    path: "/users",
    name: "Users",
    component: Users,
  },
  {
    path: "/domains",
    name: "Domains",
    component: Domains,
  },
  {
    path: "/delivery",
    name: "Delivery",
    component: Delivery,
  },
  {
    path: "/integrations",
    name: "Integrations",
    component: Integrations,
  },
  {
    path: "/openbao",
    name: "OpenBao",
    component: OpenBao,
  },
  {
    path: "/about",
    name: "About",
    // route level code-splitting
    // this generates a separate chunk (about.[hash].js) for this route
    // which is lazy-loaded when the route is visited.
    component: () =>
      import(/* webpackChunkName: "about" */ "../views/About.vue"),
  },
];

const router = new VueRouter({
  base: process.env.BASE_URL,
  routes,
});

export default router;
