/* Fabric Console &mdash; real-time operations UI (jQuery)
   Handles navigation, REST calls, WebSocket streaming, canvas map, and all views. */
(function () {
  "use strict";

  const API = "/api/v1";

  // ----------------------------------------------------------------- helpers
  function api(path, opts) {
    opts = opts || {};
    return $.ajax({
      url: API + path,
      method: opts.method || "GET",
      contentType: "application/json",
      data: opts.body ? JSON.stringify(opts.body) : undefined,
      dataType: "json",
    });
  }
  function esc(s) { return $("<div>").text(s == null ? "" : String(s)).html(); }
  function fmtBytes(n) {
    n = n || 0; const u = ["B", "K", "M", "G", "T"]; let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return n.toFixed(n < 10 && i > 0 ? 1 : 0) + u[i];
  }
  function timeAgo(ts) {
    if (!ts) return "never";
    const d = (Date.now() - new Date(ts).getTime()) / 1000;
    if (d < 60) return Math.max(0, Math.floor(d)) + "s ago";
    if (d < 3600) return Math.floor(d / 60) + "m ago";
    if (d < 86400) return Math.floor(d / 3600) + "h ago";
    return Math.floor(d / 86400) + "d ago";
  }
  function hhmmss(ts) { const d = ts ? new Date(ts) : new Date(); return d.toTimeString().slice(0, 8); }
  function pill(text, cls) { return '<span class="pill ' + (cls || "") + '"><span class="dot"></span>' + esc(text) + "</span>"; }

  // Shared table-row actions: an optional primary button + a "..." overflow menu.
  // primary = {label, onclick, cls}; items = [{label, onclick, danger} | {sep:true}].
  function menuItem(it) {
    if (it.sep) return "<div class='sep'></div>";
    const cls = it.danger ? " class='danger'" : "";
    return "<button" + cls + " onclick=\"" + it.onclick + ";Fabric.closeMenus()\">" + esc(it.label) + "</button>";
  }
  function actionMenu(primary, items) {
    let html = "<div class='row-actions'>";
    if (primary) html += "<button class='btn sm " + (primary.cls || "") + "' onclick=\"" + primary.onclick + "\">" + esc(primary.label) + "</button>";
    html += "<div class='menu-wrap'><button class='menu-btn' title='More actions' onclick=\"Fabric.toggleMenu(event, this)\">&hellip;</button>" +
      "<div class='menu-pop'>" + items.map(menuItem).join("") + "</div></div></div>";
    return html;
  }
  function toggleMenu(ev, btn) {
    ev.stopPropagation();
    const pop = btn.nextElementSibling;
    const wasOpen = pop.classList.contains("open");
    closeMenus();
    if (!wasOpen) pop.classList.add("open");
  }
  function closeMenus() {
    const open = document.querySelectorAll(".menu-pop.open");
    for (let i = 0; i < open.length; i++) open[i].classList.remove("open");
  }

  function toast(msg, kind) {
    const t = $('<div class="toast ' + (kind || "") + '">' + esc(msg) + "</div>");
    $("#toasts").append(t);
    setTimeout(function () { t.fadeOut(200, function () { t.remove(); }); }, 3800);
  }
  function openModal(html) { $("#modal").html(html); $("#overlay").addClass("open"); }
  function closeModal() { $("#overlay").removeClass("open"); }
  function openDrawer(html) { $("#drawer").html(html).addClass("open"); }
  function closeDrawer() { $("#drawer").removeClass("open"); }
  $(document).on("click", "#overlay", function (e) { if (e.target.id === "overlay") closeModal(); });

  // ----------------------------------------------------------------- navigation
  function switchView(view) {
    $(".nav-item").removeClass("active");
    $('.nav-item[data-view="' + view + '"]').addClass("active");
    $(".view").removeClass("active");
    $("#view-" + view).addClass("active");
    if (LOADERS[view]) LOADERS[view]();
    if (view === "map") requestAnimationFrame(function () { WorldMap.resize(); });
  }
  $(document).on("click", ".nav-item", function () { switchView($(this).data("view")); });

  // ----------------------------------------------------------------- dashboard
  function loadDashboard() {
    api("/analytics/summary").done(function (s) {
      const cards = [
        { label: "Nodes online", value: s.nodes.online + "/" + s.nodes.total, cls: s.nodes.online === s.nodes.total ? "good" : "", sub: "fabric members" },
        { label: "Active endpoints", value: s.endpoints.active, sub: s.endpoints.total + " provisioned" },
        { label: "Flows (24h)", value: s.flows_24h.toLocaleString(), sub: "classified" },
        { label: "Blocked (24h)", value: s.blocked_24h.toLocaleString(), cls: s.blocked_24h ? "bad" : "good", sub: "policy denials" },
      ];
      $("#statCards").html(cards.map(function (c) {
        return '<div class="panel stat"><div class="label">' + c.label + '</div>' +
          '<div class="value ' + (c.cls || "") + '">' + c.value + "</div>" +
          '<div class="sub">' + c.sub + "</div></div>";
      }).join(""));
      renderBars("#catBars", s.top_categories, "category");
      renderBars("#countryBars", s.top_countries, "country");
    });
    api("/fabric/topology").done(function (t) { WorldMap.setTopology(t); MiniTopo.render(t); });
  }
  function renderBars(sel, items, key) {
    if (!items || !items.length) { $(sel).html('<div class="empty">No data yet</div>'); return; }
    const max = Math.max.apply(null, items.map(function (i) { return i.count; }));
    $(sel).html(items.map(function (i) {
      const pct = Math.round((i.count / max) * 100);
      return '<div class="bar-row"><div class="muted">' + esc(i[key]) + "</div>" +
        '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%"></div></div>' +
        "<div style='text-align:right'>" + i.count + "</div></div>";
    }).join(""));
  }
  function pushFeed(kind, text, color) {
    const item = '<div class="feed-item"><span class="ic" style="background:' + color + '"></span>' +
      '<span class="t">' + hhmmss() + "</span><span>" + text + "</span></div>";
    const feed = $("#liveFeed"); feed.prepend(item);
    if (feed.children().length > 60) feed.children().last().remove();
  }

  // ----------------------------------------------------------------- nodes
  const ROLE_LABEL = { ingress: "Ingress", egress: "Egress", private_connector: "Connector", relay: "Relay" };
  function loadNodes() {
    api("/nodes").done(function (nodes) {
      $("#badgeNodes").text(nodes.length);
      const rows = nodes.map(function (n) {
        const roles = (n.roles || []).map(function (r) { return pill(ROLE_LABEL[r] || r, "role"); }).join(" ");
        return "<tr><td><strong>" + esc(n.name) + "</strong></td><td>" + roles + "</td>" +
          "<td class='muted'>" + (esc(n.region) || "&mdash;") + "</td>" +
          "<td>" + pill(n.status, n.status) + "</td>" +
          "<td class='mono'>" + (esc(n.fabric_addr) || "&mdash;") + "</td>" +
          "<td class='mono muted'>" + (esc(n.public_endpoint) || "&mdash;") + "</td>" +
          "<td class='muted'>" + (esc(n.version) || "&mdash;") + "</td>" +
          "<td style='text-align:right'>" + actionMenu(
          { label: "Details", onclick: "Fabric.nodeDetail('" + n.id + "')" },
          [
            { label: "Pair", onclick: "Fabric.pairNode('" + n.id + "','" + esc(n.name) + "')" },
            { label: "Configure", onclick: "Fabric.configureNode('" + n.id + "')" },
            { label: "View config", onclick: "Fabric.viewNodeConfig('" + n.id + "')" },
            { label: "Push update", onclick: "Fabric.updateNode('" + n.id + "','" + esc(n.name) + "')" },
            { sep: true },
            { label: "Delete node", danger: true, onclick: "Fabric.deleteNode('" + n.id + "')" }
          ]) +
          "</td></tr>";
      });
      $("#nodesTable tbody").html(rows.join("") || "<tr><td colspan='8' class='empty'>No nodes yet</td></tr>");
    });
  }
  function openNodeModal() {
    openModal(
      '<div class="modal-head"><h2>Add node</h2><span class="close-x" onclick="Fabric.closeModal()">&times;</span></div>' +
      '<div class="modal-body">' +
      '<div class="field"><label>Name</label><input id="n_name" placeholder="aws-egress-2" /></div>' +
      '<div class="field"><label>Roles</label><select id="n_roles" multiple size="4">' +
      '<option value="ingress">Ingress &mdash; client tunnels</option>' +
      '<option value="egress">Egress &mdash; internet exit</option>' +
      '<option value="private_connector">Private connector &mdash; corp network</option>' +
      '<option value="relay">Relay &mdash; transit / HA</option></select>' +
      '<div class="hint">Ctrl/Cmd-click to select multiple.</div></div>' +
      '<div class="field"><label>Region <span class="muted">(optional)</span></label><input id="n_region" placeholder="us-east-1" /></div>' +
      '<div class="hint">No IP addresses or CIDRs needed. The node discovers its own address and registers when it comes online &mdash; you can push network config (pools, routes, exit IPs) afterwards from <strong>Configure</strong>.</div>' +
      "</div>" +
      '<div class="modal-foot"><button class="btn ghost" onclick="Fabric.closeModal()">Cancel</button>' +
      '<button class="btn primary" onclick="Fabric.createNode()">Create node</button></div>'
    );
  }
  function createNode() {
    const roles = $("#n_roles").val() || [];
    const body = {
      name: $("#n_name").val().trim(),
      roles: roles,
      region: $("#n_region").val().trim(),
    };
    if (!body.name) return toast("Name is required", "bad");
    api("/nodes", { method: "POST", body: body })
      .done(function (n) {
        closeModal(); toast("Node created", "good"); loadNodes(); loadDashboard();
        if (n && n.id) pairNode(n.id, n.name);
      })
      .fail(function (x) { toast("Create failed: " + (x.responseJSON && x.responseJSON.detail || x.status), "bad"); });
  }
  function csv(v) { return (v || "").split(",").map(function (s) { return s.trim(); }).filter(Boolean); }

  function configureNode(id) {
    api("/nodes/" + id).done(function (n) {
      const roles = n.roles || [];
      const isIngress = roles.indexOf("ingress") >= 0;
      const isEgress = roles.indexOf("egress") >= 0;
      const isConnector = roles.indexOf("private_connector") >= 0;
      let fields = '<div class="field"><label>Region</label><input id="c_region" value="' + esc(n.region) + '" placeholder="us-east-1" /></div>' +
        '<div class="field"><label>Public endpoint <span class="muted">(auto-discovered)</span></label><input id="c_endpoint" value="' + esc(n.public_endpoint) + '" placeholder="1.2.3.4:51820" />' +
        '<div class="hint">Set at registration from the address the manager observed. Override only if the node is behind NAT/port-forwarding.</div></div>';
      if (isIngress) fields += '<div class="field"><label>Ingress endpoint pool (CIDR)</label><input id="c_pool" value="' + esc(n.endpoint_pool_cidr) + '" placeholder="100.64.0.0/16" /></div>';
      if (isConnector) fields += '<div class="field"><label>Private routes (comma CIDRs)</label><input id="c_routes" value="' + esc((n.private_routes || []).join(", ")) + '" placeholder="10.10.0.0/16" /></div>';
      if (isEgress) fields += '<div class="field"><label>Egress IP pool (comma)</label><input id="c_egress" value="' + esc((n.egress_ip_pool || []).join(", ")) + '" placeholder="203.0.113.10, 203.0.113.11" /></div>';
      openModal(
        '<div class="modal-head"><h2>Configure &ldquo;' + esc(n.name) + '&rdquo;</h2><span class="close-x" onclick="Fabric.closeModal()">&times;</span></div>' +
        '<div class="modal-body">' +
        '<p class="muted">Network config is pushed to the node on its next config poll.</p>' +
        fields +
        "</div>" +
        '<div class="modal-foot"><button class="btn ghost" onclick="Fabric.closeModal()">Cancel</button>' +
        '<button class="btn primary" onclick="Fabric.saveNodeConfig(\'' + n.id + '\')">Save &amp; push</button></div>'
      );
    }).fail(function () { toast("Failed to load node", "bad"); });
  }
  function saveNodeConfig(id) {
    const body = {};
    if ($("#c_region").length) body.region = $("#c_region").val().trim();
    if ($("#c_endpoint").length) body.public_endpoint = $("#c_endpoint").val().trim();
    if ($("#c_pool").length) body.endpoint_pool_cidr = $("#c_pool").val().trim();
    if ($("#c_routes").length) body.private_routes = csv($("#c_routes").val());
    if ($("#c_egress").length) body.egress_ip_pool = csv($("#c_egress").val());
    api("/nodes/" + id, { method: "PATCH", body: body })
      .done(function () { closeModal(); toast("Config saved &mdash; pushing to node", "good"); loadNodes(); })
      .fail(function (x) { toast("Save failed: " + (x.responseJSON && x.responseJSON.detail || x.status), "bad"); });
  }

  function pairNode(id, name) {
    api("/nodes/" + id + "/pair", { method: "POST" }).done(function (p) {
      openModal(
        '<div class="modal-head"><h2>Pair &ldquo;' + esc(name) + '&rdquo;</h2><span class="close-x" onclick="Fabric.closeModal()">&times;</span></div>' +
        '<div class="modal-body">' +
        '<p class="muted">Paste this single line on the fresh node (Ubuntu/Debian/RHEL). It downloads the agent from this management plane, then builds, installs, connects and pairs automatically. Code expires ' + timeAgo(p.expires_at).replace("ago", "from now") + ".</p>" +
        '<div class="field"><label>One-line installer</label><div class="codeblock" id="pairCmd">' + esc(p.install_command) + "</div></div>" +
        '<div class="field"><label>Pairing code</label><div class="codeblock" style="font-size:18px;text-align:center;letter-spacing:2px">' + esc(p.code) + "</div></div>" +
        "</div>" +
        '<div class="modal-foot"><button class="btn" onclick="Fabric.copy(\'pairCmd\')">Copy command</button>' +
        '<button class="btn primary" onclick="Fabric.closeModal()">Done</button></div>'
      );
    }).fail(function () { toast("Failed to issue pairing code", "bad"); });
  }
  function deleteNode(id) {
    if (!confirm("Delete this node? Its fabric peerings will be removed.")) return;
    api("/nodes/" + id, { method: "DELETE" }).done(function () { toast("Node deleted"); loadNodes(); loadDashboard(); });
  }
  function updateNode(id, name) {
    if (!confirm("Push a self-update to \"" + name + "\"? It will git-pull and restart on its next heartbeat.")) return;
    api("/nodes/" + id + "/update", { method: "POST" })
      .done(function () { toast("Update queued for " + name, "good"); })
      .fail(function () { toast("Failed to queue update", "bad"); });
  }
  function viewNodeConfig(id) {
    api("/nodes/" + id + "/config").done(function (cfg) {
      openDrawer(
        '<div class="modal-head"><h2>Node data-plane config</h2><span class="close-x" onclick="Fabric.closeDrawer()">&times;</span></div>' +
        '<div class="modal-body">' +
        '<p class="muted">Computed by the orchestrator and pushed to the node. Version <span class="mono">' + esc(cfg.version) + "</span></p>" +
        '<div class="codeblock">' + esc(JSON.stringify(cfg, null, 2)) + "</div></div>"
      );
    });
  }

  // ----------------------------------------------------------------- endpoints
  const OS_OPTS = ["windows", "macos", "linux", "ios", "android", "router"];
  const PROTO_OPTS = ["wireguard", "ipsec_ikev2", "l2tp_ipsec", "openvpn"];
  function connCell(e) {
    const c = e.conn || {};
    if (c.connected) return pill("connected", "allow");
    if (e.last_seen) return pill("idle", "");
    return "<span class='muted'>&mdash;</span>";
  }
  function loadEndpoints() {
    api("/endpoints").done(function (eps) {
      $("#badgeEndpoints").text(eps.length);
      const rows = eps.map(function (e) {
        const c = e.conn || {};
        return "<tr data-epid='" + e.id + "'><td><strong class='clickable' onclick=\"Fabric.endpointDetail('" + e.id + "')\">" + esc(e.name) + "</strong></td>" +
          "<td class='muted'>" + (esc(e.user_email || e.user_name) || "&mdash;") + "</td>" +
          "<td>" + esc(e.os) + "</td><td>" + esc(e.protocol) + "</td>" +
          "<td class='mono'>" + (esc(e.address) || "&mdash;") + "</td>" +
          "<td>" + connCell(e) + "</td>" +
          "<td class='mono muted'>" + fmtBytes(c.rx_bytes) + " / " + fmtBytes(c.tx_bytes) + "</td>" +
          "<td class='muted'>" + (e.last_seen ? timeAgo(e.last_seen) : "never") + "</td>" +
          "<td>" + (e.inspect_tls ? pill("inspect", "inspect") : pill("bypass", "")) + "</td>" +
          "<td>" + pill(e.status, e.status) + "</td>" +
          "<td style='text-align:right'>" + actionMenu(
            { label: "Get config", cls: "primary", onclick: "Fabric.endpointConfig('" + e.id + "')" },
            [
              { label: "Details", onclick: "Fabric.endpointDetail('" + e.id + "')" },
              { label: "Edit", onclick: "Fabric.editEndpoint('" + e.id + "')" },
              { label: "Share link", onclick: "Fabric.shareEndpoint('" + e.id + "')" },
              { sep: true },
              { label: "Revoke access", danger: true, onclick: "Fabric.revokeEndpoint('" + e.id + "')" },
              { label: "Delete", danger: true, onclick: "Fabric.deleteEndpoint('" + e.id + "')" }
            ]) + "</td></tr>";
      });
      $("#endpointsTable tbody").html(rows.join("") || "<tr><td colspan='11' class='empty'>No endpoints yet</td></tr>");
    });
  }
  function openEndpointModal() {
    api("/nodes").done(function (nodes) {
      const ingress = nodes.filter(function (n) { return (n.roles || []).indexOf("ingress") >= 0; });
      openModal(
        '<div class="modal-head"><h2>New endpoint</h2><span class="close-x" onclick="Fabric.closeModal()">&times;</span></div>' +
        '<div class="modal-body">' +
        '<div class="field"><label>Name</label><input id="e_name" placeholder="alice-laptop" /></div>' +
        '<div class="row"><div class="field"><label>User email</label><input id="e_email" placeholder="alice@mcnutt.cloud" /></div>' +
        '<div class="field"><label>User UID</label><input id="e_uid" placeholder="u_..." /></div></div>' +
        '<div class="row"><div class="field"><label>Operating system</label><select id="e_os">' +
        OS_OPTS.map(function (o) { return "<option>" + o + "</option>"; }).join("") + "</select></div>" +
        '<div class="field"><label>Protocol</label><select id="e_proto">' +
        PROTO_OPTS.map(function (o) { return "<option>" + o + "</option>"; }).join("") + "</select></div></div>" +
        '<div class="field"><label>Ingress node</label><select id="e_ingress">' +
        ingress.map(function (n) { return '<option value="' + n.id + '">' + esc(n.name) + " (" + esc(n.region) + ")</option>"; }).join("") +
        (ingress.length ? "" : '<option value="">&mdash; no ingress node &mdash;</option>') + "</select></div>" +
        '<div class="field"><label><input type="checkbox" id="e_inspect" checked style="width:auto"> Enable TLS inspection</label></div>' +
        "</div>" +
        '<div class="modal-foot"><button class="btn ghost" onclick="Fabric.closeModal()">Cancel</button>' +
        '<button class="btn primary" onclick="Fabric.createEndpoint()">Create &amp; generate</button></div>'
      );
    });
  }
  function createEndpoint() {
    const body = {
      name: $("#e_name").val().trim(), user_email: $("#e_email").val().trim(), user_uid: $("#e_uid").val().trim(),
      os: $("#e_os").val(), protocol: $("#e_proto").val(),
      ingress_node_id: $("#e_ingress").val() || null, inspect_tls: $("#e_inspect").is(":checked"),
    };
    if (!body.name) return toast("Name is required", "bad");
    api("/endpoints", { method: "POST", body: body }).done(function (ep) {
      closeModal(); toast("Endpoint created", "good"); loadEndpoints();
      endpointConfig(ep.id);
    }).fail(function (x) { toast("Failed: " + (x.responseJSON && x.responseJSON.detail || x.status), "bad"); });
  }
  function endpointConfig(id) {
    api("/endpoints/" + id + "/config").done(function (b) {
      const qr = b.qr_png_b64 ? '<img src="data:image/png;base64,' + b.qr_png_b64 + '" style="width:180px;border-radius:8px;background:#fff;padding:8px"/>' : "";
      const steps = (b.install_steps || []).map(function (s, i) { return "<li style='margin-bottom:6px'>" + esc(s) + "</li>"; }).join("");
      openDrawer(
        '<div class="modal-head"><h2>' + esc(b.endpoint.name) + ' &middot; config</h2><span class="close-x" onclick="Fabric.closeDrawer()">&times;</span></div>' +
        '<div class="modal-body">' +
        '<div class="flex" style="align-items:flex-start;gap:20px">' +
        '<div style="flex:1">' +
        '<div class="field"><label>' + esc(b.filename) + '</label><div class="codeblock" id="epcfg">' + esc(b.config_text) + "</div></div>" +
        '<div class="flex gap"><button class="btn" onclick="Fabric.copy(\'epcfg\')">Copy</button>' +
        '<button class="btn primary" onclick="Fabric.download(\'' + esc(b.filename) + "','epcfg')\">Download</button>" +
        '<button class="btn" onclick="Fabric.shareEndpoint(\'' + b.endpoint.id + '\')">Share link</button>' +
        '<a class="btn ghost" href="/api/v1/pki/trusted-root.pem">Trusted root</a></div>' +
        '<div id="shareBox" class="mt"></div>' +
        "</div>" + (qr ? '<div style="text-align:center"><div class="muted" style="font-size:11px;margin-bottom:6px">Scan (mobile)</div>' + qr + "</div>" : "") +
        "</div>" +
        '<div class="mt"><h3 style="font-size:13px">Install steps (' + esc(b.os) + " / " + esc(b.protocol) + ")</h3><ol class='muted' style='padding-left:18px'>" + steps + "</ol></div>" +
        "</div>"
      );
    }).fail(function () { toast("Could not generate config", "bad"); });
  }
  function revokeEndpoint(id) {
    if (!confirm("Revoke this endpoint's access? The record is kept but the tunnel is dropped.")) return;
    api("/endpoints/" + id + "/revoke", { method: "POST" })
      .done(function () { toast("Endpoint revoked"); closeDrawer(); loadEndpoints(); })
      .fail(function (x) { toast("Revoke failed: " + (x.responseJSON && x.responseJSON.detail || x.status), "bad"); });
  }
  function deleteEndpoint(id) {
    if (!confirm("Permanently delete this endpoint? This removes its record and any provisioning links, and the device loses access on the next config push.")) return;
    api("/endpoints/" + id, { method: "DELETE" })
      .done(function () { toast("Endpoint deleted"); closeDrawer(); loadEndpoints(); loadDashboard(); })
      .fail(function (x) { toast("Delete failed: " + (x.responseJSON && x.responseJSON.detail || x.status), "bad"); });
  }
  function editEndpoint(id) {
    api("/nodes").done(function (nodes) {
      const ingress = nodes.filter(function (n) { return (n.roles || []).indexOf("ingress") >= 0; });
      api("/endpoints/" + id).done(function (e) {
        function sel(v, cur) { return v === cur ? " selected" : ""; }
        openModal(
          '<div class="modal-head"><h2>Edit endpoint</h2><span class="close-x" onclick="Fabric.closeModal()">&times;</span></div>' +
          '<div class="modal-body">' +
          '<div class="field"><label>Name</label><input id="ee_name" value="' + esc(e.name) + '" /></div>' +
          '<div class="row"><div class="field"><label>User email</label><input id="ee_email" value="' + esc(e.user_email) + '" /></div>' +
          '<div class="field"><label>User name</label><input id="ee_uname" value="' + esc(e.user_name) + '" /></div></div>' +
          '<div class="field"><label>User UID</label><input id="ee_uid" value="' + esc(e.user_uid) + '" /></div>' +
          '<div class="row"><div class="field"><label>Operating system</label><select id="ee_os">' +
          OS_OPTS.map(function (o) { return "<option" + sel(o, e.os) + ">" + o + "</option>"; }).join("") + "</select></div>" +
          '<div class="field"><label>Protocol</label><select id="ee_proto">' +
          PROTO_OPTS.map(function (o) { return "<option" + sel(o, e.protocol) + ">" + o + "</option>"; }).join("") + "</select></div></div>" +
          '<div class="field"><label>Ingress node</label><select id="ee_ingress">' +
          ingress.map(function (n) { return '<option value="' + n.id + '"' + sel(n.id, e.ingress_node_id) + ">" + esc(n.name) + " (" + esc(n.region) + ")</option>"; }).join("") +
          (ingress.length ? "" : '<option value="">&mdash; no ingress node &mdash;</option>') + "</select>" +
          '<div class="hint">Moving nodes reassigns the tunnel on the next config push; the user may need a fresh config.</div></div>' +
          '<div class="field"><label><input type="checkbox" id="ee_inspect"' + (e.inspect_tls ? " checked" : "") + ' style="width:auto"> Enable TLS inspection</label></div>' +
          "</div>" +
          '<div class="modal-foot"><button class="btn ghost" onclick="Fabric.closeModal()">Cancel</button>' +
          '<button class="btn primary" onclick="Fabric.saveEndpointEdit(\'' + e.id + '\')">Save changes</button></div>'
        );
      }).fail(function () { toast("Failed to load endpoint", "bad"); });
    }).fail(function () { toast("Failed to load nodes", "bad"); });
  }
  function saveEndpointEdit(id) {
    const body = {
      name: $("#ee_name").val().trim(),
      user_email: $("#ee_email").val().trim(),
      user_name: $("#ee_uname").val().trim(),
      user_uid: $("#ee_uid").val().trim(),
      os: $("#ee_os").val(), protocol: $("#ee_proto").val(),
      ingress_node_id: $("#ee_ingress").val() || null,
      inspect_tls: $("#ee_inspect").is(":checked"),
    };
    if (!body.name) return toast("Name is required", "bad");
    api("/endpoints/" + id, { method: "PATCH", body: body })
      .done(function () { closeModal(); toast("Endpoint updated", "good"); loadEndpoints(); })
      .fail(function (x) { toast("Update failed: " + (x.responseJSON && x.responseJSON.detail || x.status), "bad"); });
  }
  function shareEndpoint(id) {
    api("/endpoints/" + id + "/provision-link", { method: "POST" }).done(function (r) {
      const url = r.url;
      const qhtml = '<div style="text-align:center;margin-top:8px"><img alt="qr" style="width:150px;background:#fff;border-radius:8px;padding:6px" src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' + encodeURIComponent(url) + '"/></div>';
      $("#shareBox").html(
        '<div class="field"><label>Shareable provisioning link (expires ' + esc(String(r.expires_at).slice(0, 16).replace("T", " ")) + ' UTC)</label>' +
        '<div class="codeblock" id="shareUrl">' + esc(url) + "</div></div>" +
        '<div class="flex gap"><button class="btn sm" onclick="Fabric.copy(\'shareUrl\')">Copy link</button>' +
        '<a class="btn sm ghost" href="' + esc(url) + '" target="_blank" rel="noopener">Open</a>' +
        '<a class="btn sm ghost" href="mailto:?subject=Your%20Fabric%20VPN&body=Open%20this%20on%20your%20phone%20to%20set%20up%20your%20secure%20connection%3A%20' + encodeURIComponent(url) + '">Email to user</a></div>' +
        qhtml
      );
    }).fail(function () { toast("Could not create share link", "bad"); });
  }

  // ----------------------------------------------------------------- policies
  const ACTIONS = ["allow", "deny", "inspect", "bypass", "steer", "redirect", "block_page", "log", "alert"];
  const ACTION_META = {
    allow: { label: "Allow", desc: "Permit the traffic", tone: "up" },
    deny: { label: "Block", desc: "Drop the connection", tone: "bad" },
    inspect: { label: "Inspect (TLS)", desc: "Decrypt & scan then allow", tone: "inspect" },
    bypass: { label: "Bypass inspection", desc: "Allow without decrypting", tone: "" },
    steer: { label: "Steer egress", desc: "Force a specific exit node/region", tone: "role", param: "steer" },
    redirect: { label: "Redirect", desc: "Send to another URL", tone: "role", param: "redirect" },
    block_page: { label: "Block page", desc: "Show a notice to the user", tone: "bad", param: "block_page" },
    log: { label: "Log only", desc: "Record, take no action", tone: "" },
    alert: { label: "Alert", desc: "Notify security team", tone: "role" },
  };
  const CATEGORY_OPTS = ["social-media", "streaming", "cloud", "productivity", "developer", "finance",
    "news", "gaming", "advertising", "malware", "internal-app", "file-share", "uncategorized"];
  function loadPolicies() {
    api("/policies").done(function (pols) {
      if (!pols.length) { $("#policiesList").html('<div class="empty">No policies. Create one to steer and control traffic.</div>'); return; }
      $("#policiesList").html(pols.map(function (p) {
        const rules = (p.rules || []).map(function (r) {
          const m = [];
          if (r.match_roles.length) m.push("roles in [" + r.match_roles.join(",") + "]");
          if (r.match_categories.length) m.push("cat in [" + r.match_categories.join(",") + "]");
          if (r.match_domains.length) m.push("dom in [" + r.match_domains.join(",") + "]");
          if (r.match_dst_cidrs.length) m.push("dst in [" + r.match_dst_cidrs.join(",") + "]");
          if (r.match_ports.length) m.push("port in [" + r.match_ports.join(",") + "]");
          if (r.match_countries.length) m.push("geo in [" + r.match_countries.join(",") + "]");
          return "<tr><td class='muted'>" + (r.order) + "</td><td>" + (esc(r.name) || "&mdash;") + "</td>" +
            "<td class='mono muted' style='font-size:11px'>" + (m.join(" &middot; ") || "any") + "</td>" +
            "<td>" + pill(r.action, r.action) + "</td></tr>";
        }).join("");
        return '<div class="panel"><div class="panel-head"><div class="flex">' +
          "<h3>" + esc(p.name) + "</h3>" + pill(p.enabled ? "enabled" : "disabled", p.enabled ? "up" : "") +
          '<span class="muted" style="font-size:12px">priority ' + p.priority + " &middot; default " + p.default_action + "</span></div>" +
          '<div class="flex gap"><button class="btn sm" onclick="Fabric.editPolicy(\'' + p.id + '\')">Edit</button>' +
          '<button class="btn sm danger" onclick="Fabric.deletePolicy(\'' + p.id + '\')">Delete</button></div></div>' +
          '<div class="panel-body" style="padding:0"><table class="data compact"><thead><tr><th>#</th><th>Rule</th><th>Match</th><th>Action</th></tr></thead><tbody>' +
          (rules || "<tr><td colspan=4 class='muted'>No rules</td></tr>") + "</tbody></table>" +
          '<div class="muted" style="padding:8px 12px;font-size:12px">' + esc(p.description || "") + "</div></div></div>";
      }).join(""));
    });
  }
  let policyRules = [];
  function openPolicyModal(existing) {
    policyRules = existing ? existing.rules.map(cloneRule) : [];
    openModal(
      '<div class="modal-head"><h2>' + (existing ? "Edit" : "New") + ' policy</h2><span class="close-x" onclick="Fabric.closeModal()">&times;</span></div>' +
      '<div class="modal-body">' +
      '<input type="hidden" id="p_id" value="' + (existing ? existing.id : "") + '"/>' +
      '<div class="row"><div class="field"><label>Name</label><input id="p_name" value="' + (existing ? esc(existing.name) : "") + '"/></div>' +
      '<div class="field"><label>Priority</label><input id="p_priority" type="number" value="' + (existing ? existing.priority : 100) + '"/></div></div>' +
      '<div class="row"><div class="field"><label>Default action</label><select id="p_default">' +
      ACTIONS.map(function (a) { return '<option value="' + a + '" ' + (existing && existing.default_action === a ? "selected" : "") + ">" + ACTION_META[a].label + "</option>"; }).join("") + "</select></div>" +
      '<div class="field"><label>Enabled</label><select id="p_enabled"><option value="true">Yes</option><option value="false" ' + (existing && !existing.enabled ? "selected" : "") + ">No</option></select></div></div>" +
      '<div class="field"><label>Description</label><input id="p_desc" value="' + (existing ? esc(existing.description) : "") + '"/></div>' +
      '<div class="panel-head" style="padding:8px 0"><h3>Rules (first match wins)</h3><button class="btn sm" onclick="Fabric.addRule()">+ Add rule</button></div>' +
      '<div id="ruleEditor"></div>' +
      "</div>" +
      '<div class="modal-foot"><button class="btn ghost" onclick="Fabric.closeModal()">Cancel</button>' +
      '<button class="btn primary" onclick="Fabric.savePolicy()">Save policy</button></div>'
    );
    renderRules();
  }
  function cloneRule(r) { return JSON.parse(JSON.stringify(r)); }
  function blankRule() {
    return { name: "", enabled: true, order: policyRules.length, match_roles: [], match_users: [], match_src_cidrs: [],
      match_endpoints: [], match_node_roles: [], match_dst_cidrs: [], match_domains: [], match_categories: [],
      match_ports: [], match_protocols: [], match_countries: [], match_asns: [], match_time: {}, action: "allow", action_params: {} };
  }
  function addRule() { policyRules.push(blankRule()); renderRules(); }
  function ruleSummary(r) {
    const when = [];
    if (r.match_roles.length) when.push("user role " + r.match_roles.join("/"));
    if (r.match_categories.length) when.push("category " + r.match_categories.join("/"));
    if (r.match_domains.length) when.push("domain " + r.match_domains.slice(0, 3).join("/") + (r.match_domains.length > 3 ? "&hellip;" : ""));
    if (r.match_dst_cidrs.length) when.push("dst " + r.match_dst_cidrs.join("/"));
    if (r.match_ports.length) when.push("port " + r.match_ports.join("/"));
    if (r.match_countries.length) when.push("country " + r.match_countries.join("/"));
    const cond = when.length ? when.join(" and ") : "any traffic";
    const meta = ACTION_META[r.action] || { label: r.action };
    return "When <strong>" + cond + "</strong> then <strong>" + meta.label + "</strong>";
  }
  function actionParamFields(r, i) {
    const p = r.action_params || {};
    const meta = ACTION_META[r.action] || {};
    if (meta.param === "steer") {
      return '<div class="field"><label>Steer to egress node/region</label><input data-ap="' + i + '" data-k="egress" placeholder="aws-egress-1 or eu-west-1" value="' + esc(p.egress || "") + '"/></div>';
    }
    if (meta.param === "redirect") {
      return '<div class="field"><label>Redirect URL</label><input data-ap="' + i + '" data-k="url" placeholder="https://portal.example.com" value="' + esc(p.url || "") + '"/></div>';
    }
    if (meta.param === "block_page") {
      return '<div class="field"><label>Block message shown to user</label><input data-ap="' + i + '" data-k="message" placeholder="Blocked by security policy" value="' + esc(p.message || "") + '"/></div>';
    }
    return "";
  }
  function categoryChips(r, i) {
    return CATEGORY_OPTS.map(function (c) {
      const on = r.match_categories.indexOf(c) >= 0;
      return '<label class="chip' + (on ? " on" : "") + '"><input type="checkbox" data-cat="' + i + '" value="' + c + '" ' + (on ? "checked" : "") + " style='display:none'/>" + c + "</label>";
    }).join("");
  }
  function renderRules() {
    $("#ruleEditor").html(policyRules.map(function (r, i) {
      const advId = "adv_" + i;
      return '<div class="panel" style="margin-bottom:10px"><div class="panel-body">' +
        '<div class="muted" style="font-size:12px;margin-bottom:8px">#' + (i + 1) + " &middot; " + ruleSummary(r) + "</div>" +
        '<div class="row"><div class="field"><label>Rule name</label><input data-r="' + i + '" data-f="name" placeholder="e.g. Block malware" value="' + esc(r.name) + '"/></div>' +
        '<div class="field"><label>Then do</label><select data-r="' + i + '" data-f="action">' +
        ACTIONS.map(function (a) { return '<option value="' + a + '" ' + (r.action === a ? "selected" : "") + ">" + ACTION_META[a].label + " &mdash; " + ACTION_META[a].desc + "</option>"; }).join("") + "</select></div></div>" +
        actionParamFields(r, i) +
        '<div class="field"><label>When category is any of</label><div class="chips">' + categoryChips(r, i) + "</div></div>" +
        '<div class="row"><div class="field"><label>User roles</label><input data-r="' + i + '" data-f="match_roles" placeholder="contractor, finance" value="' + esc(r.match_roles.join(", ")) + '"/></div>' +
        '<div class="field"><label>Domains</label><input data-r="' + i + '" data-f="match_domains" placeholder="*.example.com" value="' + esc(r.match_domains.join(", ")) + '"/></div></div>' +
        '<div class="row"><div class="field"><label>Destination CIDRs</label><input data-r="' + i + '" data-f="match_dst_cidrs" placeholder="10.0.0.0/8" value="' + esc(r.match_dst_cidrs.join(", ")) + '"/></div>' +
        '<div class="field"><label>Ports</label><input data-r="' + i + '" data-f="match_ports" placeholder="443, 8443" value="' + esc(r.match_ports.join(", ")) + '"/></div></div>' +
        '<div class="row"><div class="field"><label>Countries</label><input data-r="' + i + '" data-f="match_countries" placeholder="RU, CN" value="' + esc(r.match_countries.join(", ")) + '"/></div>' +
        '<div class="field"><label>&nbsp;</label><a class="btn sm ghost" onclick="Fabric.toggleAdvanced(\'' + advId + '\')">Advanced JSON</a></div></div>' +
        '<div id="' + advId + '" style="display:none"><div class="field"><label>Action params (raw JSON, optional)</label><input data-r="' + i + '" data-f="action_params" value=\'' + esc(JSON.stringify(r.action_params || {})) + '\'/></div></div>' +
        '<button class="btn sm danger" onclick="Fabric.removeRule(' + i + ')">Remove rule</button>' +
        "</div></div>";
    }).join("") || '<div class="muted">No rules yet. Click &ldquo;+ Add rule&rdquo; to start.</div>');
  }
  function toggleAdvanced(id) { const el = document.getElementById(id); if (el) el.style.display = el.style.display === "none" ? "block" : "none"; }
  $(document).on("change keyup", "#ruleEditor input[data-r], #ruleEditor select[data-r]", function () {
    const i = $(this).data("r"), f = $(this).data("f"); let v = $(this).val();
    if (f === "action_params") { try { v = JSON.parse(v || "{}"); } catch (e) { v = {}; } }
    else if (["match_roles", "match_categories", "match_domains", "match_dst_cidrs", "match_ports", "match_countries"].indexOf(f) >= 0) {
      v = csv(v).map(function (x) { return f === "match_ports" ? (isNaN(+x) ? x : +x) : x; });
    }
    policyRules[i][f] = v;
    if (f === "action") renderRules();
    else refreshRuleSummary(i);
  });
  $(document).on("change", "#ruleEditor input[data-cat]", function () {
    const i = $(this).data("cat"), c = $(this).val(), on = $(this).is(":checked");
    const arr = policyRules[i].match_categories;
    const idx = arr.indexOf(c);
    if (on && idx < 0) arr.push(c);
    if (!on && idx >= 0) arr.splice(idx, 1);
    $(this).parent().toggleClass("on", on);
    refreshRuleSummary(i);
  });
  $(document).on("change keyup", "#ruleEditor input[data-ap]", function () {
    const i = $(this).data("ap"), k = $(this).data("k");
    policyRules[i].action_params = policyRules[i].action_params || {};
    policyRules[i].action_params[k] = $(this).val();
  });
  function refreshRuleSummary(i) {
    const panel = $("#ruleEditor .panel").eq(i).find(".muted").first();
    if (panel.length) panel.html("#" + (i + 1) + " &middot; " + ruleSummary(policyRules[i]));
  }
  function removeRule(i) { policyRules.splice(i, 1); renderRules(); }
  function savePolicy() {
    const id = $("#p_id").val();
    const body = {
      name: $("#p_name").val().trim(), description: $("#p_desc").val(),
      enabled: $("#p_enabled").val() === "true", priority: +$("#p_priority").val() || 100,
      default_action: $("#p_default").val(), rules: policyRules,
    };
    if (!body.name) return toast("Name required", "bad");
    const req = id ? api("/policies/" + id, { method: "PUT", body: body }) : api("/policies", { method: "POST", body: body });
    req.done(function () { closeModal(); toast("Policy saved", "good"); loadPolicies(); })
      .fail(function (x) { toast("Save failed: " + (x.responseJSON && x.responseJSON.detail || x.status), "bad"); });
  }
  function editPolicy(id) { api("/policies").done(function (pols) { const p = pols.find(function (x) { return x.id === id; }); if (p) openPolicyModal(p); }); }
  function deletePolicy(id) { if (!confirm("Delete policy?")) return; api("/policies/" + id, { method: "DELETE" }).done(function () { toast("Deleted"); loadPolicies(); }); }

  // ----------------------------------------------------------------- flows & dns
  let flowsCache = {}, dnsCache = {};
  function loadFlows() {
    api("/flows?limit=200").done(function (rows) {
      flowsCache = {};
      rows.forEach(function (f) { flowsCache[f.id] = f; });
      $("#flowsTable tbody").html(rows.map(flowRow).join("") || "<tr><td colspan='9' class='empty'>Awaiting traffic&hellip;</td></tr>");
    });
  }
  function flowRow(f) {
    const click = f.id ? " class='clickable' onclick=\"Fabric.flowDetail(" + f.id + ")\"" : "";
    return "<tr" + click + "><td class='mono muted'>" + hhmmss(f.ts) + "</td>" +
      "<td>" + (esc(f.user_uid || f.src_ip) || "&mdash;") + "</td>" +
      "<td><strong>" + esc(f.domain || f.sni || f.dst_ip) + "</strong><span class='muted'>:" + f.dst_port + "</span></td>" +
      "<td>" + (f.category ? pill(f.category, "") : "<span class='muted'>&mdash;</span>") + "</td>" +
      "<td class='muted'>" + esc(f.country || "") + (f.geo && f.geo.city ? " &middot; " + esc(f.geo.city) : "") + "</td>" +
      "<td class='muted'>" + (esc(f.isp || (f.asn ? "AS" + f.asn : "")) || "&mdash;") + "</td>" +
      "<td class='mono muted'>" + (esc(f.egress_ip) || "&mdash;") + "</td>" +
      "<td>" + pill(f.verdict, f.verdict) + "</td>" +
      "<td class='mono'>" + fmtBytes(f.tx_bytes + f.rx_bytes) + "</td></tr>";
  }
  const HOP_ICON = { endpoint: "&#128241;", ingress: "&#128274;", egress: "&#127760;", connector: "&#127970;", internet: "&#127760;", private: "&#127970;" };
  function flowPathHtml(path) {
    return (path || []).map(function (h, i) {
      const arrow = i < path.length - 1 ? '<div class="hop-arrow">&rarr;</div>' : "";
      const sub = [h.detail, h.region, h.country, h.user, h.os].filter(Boolean).map(esc).join(" &middot; ");
      return '<div class="hop"><div class="hop-ic">' + (HOP_ICON[h.kind] || "&#8226;") + "</div>" +
        '<div class="hop-label">' + esc(h.label) + "</div>" +
        '<div class="hop-name">' + esc(h.name || "") + "</div>" +
        (sub ? '<div class="hop-sub muted">' + sub + "</div>" : "") + "</div>" + arrow;
    }).join("");
  }
  function kv(label, val) {
    if (val === undefined || val === null || val === "") return "";
    return '<div class="kv"><span class="k muted">' + esc(label) + '</span><span class="v mono">' + esc(String(val)) + "</span></div>";
  }
  function flowDetail(id) {
    api("/flows/" + id).done(function (f) {
      const m = f.meta || {};
      const heur = kv("App", f.app) + kv("HTTP host", m.http_host) + kv("Method", m.http_method) +
        kv("Path", m.http_path) + kv("Status", m.http_status) + kv("Content-type", m.content_type) +
        kv("User-agent", m.user_agent) + kv("TLS", m.tls_version) + kv("Cipher", m.cipher) +
        kv("JA3", f.ja3) + kv("JA3S", m.ja3s) + kv("Inspected", m.inspected === true ? "yes" : (m.inspected === false ? "no" : "")) +
        kv("Packets", m.packets) + kv("Duration", f.duration_ms ? f.duration_ms + " ms" : "");
      const net = kv("Protocol", f.protocol) + kv("Dst IP", f.dst_ip) + kv("Port", f.dst_port) +
        kv("Country", f.country) + kv("ISP", f.isp) + kv("ASN", f.asn ? "AS" + f.asn : "") +
        kv("Egress IP", f.egress_ip) + kv("Category", f.category) + kv("Risk", f.risk) +
        kv("Sent", fmtBytes(f.tx_bytes)) + kv("Received", fmtBytes(f.rx_bytes));
      const payload = m.payload_sample ? '<div class="field"><label>Parsed request sample</label><div class="codeblock">' + esc(m.payload_sample) + "</div></div>" : "";
      openDrawer(
        '<div class="modal-head"><h2>Flow &middot; ' + esc(f.domain || f.sni || f.dst_ip) + '</h2><span class="close-x" onclick="Fabric.closeDrawer()">&times;</span></div>' +
        '<div class="modal-body">' +
        '<div class="flex" style="justify-content:space-between;align-items:center"><div>' + pill(f.verdict, f.verdict) + " " + (f.category ? pill(f.category, "") : "") + '</div><div class="muted mono">' + hhmmss(f.ts) + "</div></div>" +
        '<h3 style="font-size:13px;margin-top:14px">Path traversed</h3><div class="hoppath">' + flowPathHtml(f.path) + "</div>" +
        '<h3 style="font-size:13px;margin-top:16px">Heuristics</h3><div class="kvgrid">' + (heur || '<span class="muted">No deep heuristics</span>') + "</div>" +
        '<h3 style="font-size:13px;margin-top:16px">Network</h3><div class="kvgrid">' + net + "</div>" +
        payload +
        "</div>"
      );
    }).fail(function () { toast("Could not load flow detail", "bad"); });
  }
  function loadDns() {
    api("/dns?limit=200").done(function (rows) {
      dnsCache = {};
      rows.forEach(function (d) { dnsCache[d.id] = d; });
      $("#dnsTable tbody").html(rows.map(dnsRow).join("") || "<tr><td colspan='7' class='empty'>Awaiting queries&hellip;</td></tr>");
    });
  }
  function dnsRow(d) {
    const click = d.id ? " class='clickable' onclick=\"Fabric.dnsDetail(" + d.id + ")\"" : "";
    return "<tr" + click + "><td class='mono muted'>" + hhmmss(d.ts) + "</td>" +
      "<td class='muted'>" + (esc(d.client_ip || d.user_uid) || "&mdash;") + "</td>" +
      "<td><strong>" + esc(d.qname) + "</strong></td><td class='muted'>" + esc(d.qtype) + "</td>" +
      "<td class='mono muted'>" + (esc(d.answer) || "&mdash;") + "</td>" +
      "<td>" + (d.category ? pill(d.category, "") : "&mdash;") + "</td>" +
      "<td>" + pill(d.action, d.action === "resolve" ? "allow" : d.action === "block" || d.action === "sinkhole" ? "deny" : "redirect") + "</td></tr>";
  }
  function dnsDetail(id) {
    const d = dnsCache[id];
    if (!d) return;
    const m = d.meta || {};
    const rows = kv("Query", d.qname) + kv("Type", d.qtype) + kv("Action", d.action) +
      kv("Answer", d.answer) + kv("Category", d.category) + kv("Client", d.client_ip) +
      kv("User", d.user_uid) + kv("Latency", d.latency_ms ? d.latency_ms + " ms" : "") +
      kv("Resolver", m.resolver) + kv("Upstream", m.upstream) + kv("TTL", m.ttl) +
      kv("Zone", m.destination_zone) + kv("App", m.app) + kv("Blocklist", m.blocklist);
    const answers = (m.answers && m.answers.length) ? '<div class="field"><label>Answers</label><div class="codeblock">' + esc(m.answers.join("\n")) + "</div></div>" : "";
    openDrawer(
      '<div class="modal-head"><h2>DNS &middot; ' + esc(d.qname) + '</h2><span class="close-x" onclick="Fabric.closeDrawer()">&times;</span></div>' +
      '<div class="modal-body"><div class="flex" style="justify-content:space-between;align-items:center"><div>' +
      pill(d.action, d.action === "resolve" ? "allow" : "deny") + " " + (d.category ? pill(d.category, "") : "") +
      '</div><div class="muted mono">' + hhmmss(d.ts) + "</div></div>" +
      '<h3 style="font-size:13px;margin-top:14px">Resolution</h3><div class="kvgrid">' + rows + "</div>" + answers + "</div>"
    );
  }

  // ----------------------------------------------------------------- pki
  function loadPki() {
    api("/pki/status").done(function (s) {
      const kinds = [["root_ca", "Root CA"], ["infra_ca", "Infrastructure CA"], ["endpoint_ca", "Endpoint CA"], ["mitm_ca", "Inspection (MITM) CA"]];
      $("#pkiCards").html(kinds.map(function (k) {
        const c = s[k[0]];
        var body;
        if (c) {
          body = '<div class="value good" style="font-size:16px">Active</div>' +
            '<div class="sub mono">' + esc(c.serial.slice(0, 16)) + "&hellip;</div>" +
            '<div class="sub">expires ' + new Date(c.not_after).toLocaleDateString() + "</div>";
        } else {
          body = '<div class="value" style="font-size:16px">&mdash;</div>' +
            '<div class="sub">not initialised</div>';
        }
        return '<div class="panel stat"><div class="label">' + k[1] + "</div>" + body + "</div>";
      }).join(""));
    });
    api("/pki/certificates").done(function (certs) {
      pkiCache = {};
      certs.forEach(function (c) { pkiCache[c.serial] = c; });
      $("#certsTable tbody").html(certs.map(function (c) {
        return "<tr class='clickable' onclick=\"Fabric.certDetail('" + esc(c.serial) + "')\"><td>" + pill(c.kind, "role") + "</td><td>" + esc(c.subject_cn) + "</td>" +
          "<td class='mono muted'>" + esc(c.serial.slice(0, 20)) + "&hellip;</td>" +
          "<td class='muted'>" + new Date(c.not_after).toLocaleDateString() + "</td>" +
          "<td class='mono muted'>" + (esc(c.subject_ref) || "&mdash;") + "</td>" +
          "<td>" + pill(c.revoked ? "revoked" : "valid", c.revoked ? "revoked" : "up") + "</td></tr>";
      }).join("") || "<tr><td colspan='6' class='empty'>No certificates</td></tr>");
    });
  }
  let pkiCache = {};
  function certDetail(serial) {
    const c = pkiCache[serial];
    if (!c) return;
    const rows = kv("Kind", c.kind) + kv("Subject CN", c.subject_cn) + kv("Subject ref", c.subject_ref) +
      kv("Serial", c.serial) + kv("Issuer", c.issuer_cn) + kv("Not before", c.not_before ? new Date(c.not_before).toLocaleString() : "") +
      kv("Not after", c.not_after ? new Date(c.not_after).toLocaleString() : "") +
      kv("Status", c.revoked ? "revoked" : "valid") + kv("Fingerprint", c.fingerprint);
    const sans = (c.sans && c.sans.length) ? '<div class="field"><label>SANs</label><div class="codeblock">' + esc(c.sans.join("\n")) + "</div></div>" : "";
    openDrawer(
      '<div class="modal-head"><h2>Certificate &middot; ' + esc(c.subject_cn) + '</h2><span class="close-x" onclick="Fabric.closeDrawer()">&times;</span></div>' +
      '<div class="modal-body"><div class="flex" style="justify-content:space-between;align-items:center"><div>' +
      pill(c.kind, "role") + " " + pill(c.revoked ? "revoked" : "valid", c.revoked ? "revoked" : "up") + "</div></div>" +
      '<h3 style="font-size:13px;margin-top:14px">Details</h3><div class="kvgrid">' + rows + "</div>" + sans +
      '<div class="flex gap mt"><a class="btn sm ghost" href="/api/v1/pki/trusted-root.pem">Download trusted root</a></div></div>'
    );
  }

  // ----------------------------------------------------------------- canvas maps
  const REGION_COORDS = {
    "us-east-1": [39, -77], "us-west-2": [45, -122], "eu-west-1": [53, -6], "eu-central-1": [50, 8],
    "ap-southeast-1": [1.3, 103], "ap-northeast-1": [35, 139], "dc-a": [41, -87], "dc-b": [33, -96], "": [20, 0],
  };
  function project(lat, lon, w, h) { return [(lon + 180) / 360 * w, (90 - lat) / 180 * h]; }
  const ROLE_COLOR = { ingress: "#3b82f6", egress: "#22c55e", private_connector: "#8b5cf6", relay: "#64748b" };

  // Simplified continent outlines ([lon, lat] rings) for geographic context.
  const CONTINENTS = [
    [[-168,66],[-165,60],[-158,57],[-153,58],[-146,60],[-140,60],[-133,55],[-130,52],[-124,48],[-124,40],[-120,34],[-117,32],[-110,23],[-105,20],[-97,16],[-95,18],[-90,20],[-88,21],[-83,10],[-81,8],[-80,25],[-81,31],[-76,35],[-70,42],[-67,45],[-60,47],[-56,52],[-64,60],[-78,62],[-85,70],[-95,70],[-110,68],[-125,70],[-140,70],[-156,71],[-168,66]],
    [[-81,6],[-78,0],[-80,-4],[-75,-14],[-71,-18],[-70,-23],[-72,-30],[-73,-37],[-74,-44],[-75,-50],[-69,-55],[-65,-55],[-64,-42],[-62,-38],[-58,-34],[-53,-33],[-48,-25],[-40,-20],[-35,-8],[-35,-5],[-44,0],[-50,4],[-52,5],[-60,8],[-66,11],[-72,11],[-77,8],[-81,6]],
    [[-10,36],[-9,44],[-4,48],[2,51],[8,54],[10,58],[15,65],[25,71],[30,66],[28,58],[38,55],[40,48],[30,45],[28,41],[20,40],[14,38],[8,44],[0,40],[-6,36],[-10,36]],
    [[-17,15],[-16,20],[-10,27],[-6,32],[0,36],[10,37],[11,33],[20,32],[25,32],[32,31],[34,28],[43,12],[51,12],[48,5],[42,-1],[40,-10],[35,-18],[32,-25],[26,-33],[20,-34],[18,-34],[15,-27],[13,-17],[9,-1],[8,4],[3,6],[-8,4],[-13,8],[-17,15]],
    [[40,46],[45,40],[50,45],[55,52],[60,55],[65,55],[75,55],[85,50],[90,52],[100,53],[108,50],[115,53],[120,53],[127,50],[135,55],[142,59],[145,62],[160,60],[170,66],[178,68],[180,72],[160,72],[140,73],[120,73],[100,76],[80,74],[70,73],[60,70],[55,68],[45,66],[40,68],[33,70],[30,66],[38,60],[45,55],[48,50],[40,46]],
    [[113,-22],[114,-28],[115,-34],[120,-34],[129,-32],[137,-33],[140,-38],[147,-43],[150,-38],[153,-30],[153,-25],[146,-19],[142,-11],[135,-12],[130,-12],[124,-16],[122,-18],[115,-21],[113,-22]],
    [[68,23],[70,20],[73,18],[77,8],[80,10],[80,15],[85,20],[88,22],[90,22],[89,26],[80,30],[72,25],[68,23]],
  ];

  const WorldMap = (function () {
    // Fixed equirectangular world bounds (degrees) mapped to the canvas.
    const LON0 = -170, LON1 = 195, LAT0 = 82, LAT1 = -56;
    let cv, ctx, topo = { nodes: [], links: [] }, pulses = [], raf, dpr = 1;
    let posById = {}, viewW = 0, viewH = 0, padX = 0, padY = 0, showFlows = true, clickBound = false;

    function init() {
      cv = document.getElementById("worldMap"); if (!cv) return;
      ctx = cv.getContext("2d");
      if (!clickBound) { cv.addEventListener("click", onClick); clickBound = true; }
      resize(); loop();
    }
    function resize() {
      if (!cv || !ctx) return;
      dpr = window.devicePixelRatio || 1;
      viewW = cv.clientWidth; viewH = cv.clientHeight;
      cv.width = Math.round(viewW * dpr); cv.height = Math.round(viewH * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      padX = viewW * 0.03; padY = viewH * 0.05;
      relayout();
    }
    function setTopology(t) { topo = t || topo; relayout(); }
    function setFlows(on) { showFlows = !!on; if (!showFlows) pulses = []; }

    function proj(lat, lon) {
      const x = padX + (lon - LON0) / (LON1 - LON0) * (viewW - padX * 2);
      const y = padY + (LAT0 - lat) / (LAT0 - LAT1) * (viewH - padY * 2);
      return [x, y];
    }

    // Node geo coords, spreading same-region nodes into a small ring.
    function geoCoords() {
      const groups = {};
      (topo.nodes || []).forEach(function (n) {
        const c = REGION_COORDS[n.region] || REGION_COORDS[""];
        const key = c[0] + "," + c[1];
        (groups[key] = groups[key] || []).push({ n: n, c: c });
      });
      const out = {};
      Object.keys(groups).forEach(function (key) {
        const g = groups[key];
        if (g.length === 1) { out[g[0].n.id] = { lat: g[0].c[0], lon: g[0].c[1] }; return; }
        const r = 4;
        g.forEach(function (item, i) {
          const a = (i / g.length) * Math.PI * 2 - Math.PI / 2;
          out[item.n.id] = { lat: item.c[0] + Math.sin(a) * r, lon: item.c[1] + Math.cos(a) * r * 1.6 };
        });
      });
      return out;
    }
    function relayout() {
      posById = {};
      if (!cv) return;
      const geo = geoCoords();
      Object.keys(geo).forEach(function (id) { posById[id] = proj(geo[id].lat, geo[id].lon); });
    }
    function nodePos(n) { return posById[n.id] || [viewW / 2, viewH / 2]; }
    function nodeById(id) { return topo.nodes.find(function (n) { return n.id === id; }); }
    function firstRole(role) { return topo.nodes.find(function (n) { return (n.roles || []).indexOf(role) >= 0; }); }

    // Build a multi-hop flow pulse: endpoint/ingress -> egress/connector -> destination.
    function addFlow(f) {
      if (!cv || !showFlows) return;
      const zone = (f.meta && f.meta.destination_zone) || (f.category === "internal-app" || f.category === "file-share" ? "private" : "internet");
      const ingress = nodeById(f.node_id) || firstRole("ingress") || topo.nodes[0];
      let egress = nodeById(f.egress_node_id);
      if (!egress) egress = zone === "private" ? firstRole("private_connector") : firstRole("egress");
      const pts = [];
      if (ingress) pts.push(nodePos(ingress));
      if (egress && (!ingress || egress.id !== ingress.id)) pts.push(nodePos(egress));
      // destination point
      let dst;
      if (zone === "private") {
        const base = egress ? nodePos(egress) : (ingress ? nodePos(ingress) : [viewW / 2, viewH / 2]);
        dst = [base[0] + 46, base[1] + 34];
      } else if (f.geo && f.geo.lat != null && (f.geo.lat || f.geo.lon)) {
        dst = proj(f.geo.lat, f.geo.lon);
      } else {
        const base = pts[pts.length - 1] || [viewW / 2, viewH / 2];
        dst = [base[0] + 80, base[1] - 40];
      }
      pts.push(dst);
      if (pts.length < 2) return;
      const denied = f.verdict === "denied";
      const color = denied ? "#ef4444" : (zone === "private" ? "#8b5cf6" : "#f59e0b");
      pulses.push({ pts: pts, t: 0, color: color, zone: zone, dst: dst });
      if (pulses.length > 90) pulses.shift();
    }
    // Back-compat: simple destination pulse from the mesh.
    function addPulse(lat, lon, color) {
      addFlow({ geo: { lat: lat, lon: lon }, verdict: color === "#ef4444" ? "denied" : "allowed" });
    }

    function polyPoint(pts, t) {
      // interpolate along the polyline by fraction t (0..1) of total length
      let total = 0; const segs = [];
      for (let i = 0; i < pts.length - 1; i++) {
        const d = Math.hypot(pts[i + 1][0] - pts[i][0], pts[i + 1][1] - pts[i][1]);
        segs.push(d); total += d;
      }
      let target = t * total;
      for (let i = 0; i < segs.length; i++) {
        if (target <= segs[i] || i === segs.length - 1) {
          const f = segs[i] ? target / segs[i] : 0;
          return [pts[i][0] + (pts[i + 1][0] - pts[i][0]) * f, pts[i][1] + (pts[i + 1][1] - pts[i][1]) * f];
        }
        target -= segs[i];
      }
      return pts[pts.length - 1];
    }
    function drawWorld() {
      // ocean
      ctx.fillStyle = "rgba(15,23,42,.35)"; ctx.fillRect(0, 0, viewW, viewH);
      // graticule
      ctx.strokeStyle = "rgba(59,130,246,.06)"; ctx.lineWidth = 1;
      for (let lon = -150; lon <= 180; lon += 30) { const a = proj(80, lon), b = proj(-50, lon); ctx.beginPath(); ctx.moveTo(a[0], a[1]); ctx.lineTo(b[0], b[1]); ctx.stroke(); }
      for (let lat = 75; lat >= -45; lat -= 30) { const a = proj(lat, -170), b = proj(lat, 195); ctx.beginPath(); ctx.moveTo(a[0], a[1]); ctx.lineTo(b[0], b[1]); ctx.stroke(); }
      // continents
      CONTINENTS.forEach(function (ring) {
        ctx.beginPath();
        ring.forEach(function (pt, i) { const p = proj(pt[1], pt[0]); if (i === 0) ctx.moveTo(p[0], p[1]); else ctx.lineTo(p[0], p[1]); });
        ctx.closePath();
        ctx.fillStyle = "rgba(51,65,85,.38)"; ctx.fill();
        ctx.strokeStyle = "rgba(100,116,139,.45)"; ctx.lineWidth = 1; ctx.stroke();
      });
    }
    function onClick(ev) {
      const rect = cv.getBoundingClientRect();
      const mx = ev.clientX - rect.left, my = ev.clientY - rect.top;
      let hit = null;
      topo.nodes.forEach(function (n) { const p = nodePos(n); if (Math.hypot(p[0] - mx, p[1] - my) <= 12) hit = n; });
      if (hit) showNodeInfo(hit);
    }
    function loop() {
      if (!ctx) return; raf = requestAnimationFrame(loop);
      ctx.clearRect(0, 0, viewW, viewH);
      drawWorld();
      // links
      topo.links.forEach(function (l) {
        const a = nodeById(l.a), b = nodeById(l.b);
        if (!a || !b) return;
        const pa = nodePos(a), pb = nodePos(b);
        if (l.status === "up") { ctx.strokeStyle = "rgba(34,197,94,.4)"; }
        else if (l.status === "degraded") { ctx.strokeStyle = "rgba(245,158,11,.4)"; }
        else { ctx.strokeStyle = "rgba(239,68,68,.3)"; }
        ctx.lineWidth = 1.5; ctx.beginPath(); ctx.moveTo(pa[0], pa[1]); ctx.lineTo(pb[0], pb[1]); ctx.stroke();
      });
      // flow pulses (multi-hop)
      pulses.forEach(function (p) {
        p.t += 0.012;
        const head = polyPoint(p.pts, Math.min(p.t, 1));
        // faint full path
        ctx.strokeStyle = p.color.replace(")", ",.12)").replace("rgb", "rgba");
        ctx.globalAlpha = 0.18; ctx.strokeStyle = p.color; ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(p.pts[0][0], p.pts[0][1]);
        for (let i = 1; i < p.pts.length; i++) ctx.lineTo(p.pts[i][0], p.pts[i][1]);
        ctx.stroke(); ctx.globalAlpha = 1;
        // moving head
        ctx.fillStyle = p.color; ctx.beginPath(); ctx.arc(head[0], head[1], 2.6, 0, 7); ctx.fill();
        // destination marker
        if (p.t > 0.6) {
          ctx.globalAlpha = Math.min((p.t - 0.6) / 0.4, 1);
          ctx.strokeStyle = p.color; ctx.lineWidth = 1.4;
          ctx.beginPath(); ctx.arc(p.dst[0], p.dst[1], 4 + (p.t - 0.6) * 8, 0, 7); ctx.stroke();
          ctx.globalAlpha = 1;
        }
      });
      pulses = pulses.filter(function (p) { return p.t < 1.05; });
      // nodes
      topo.nodes.forEach(function (n) {
        const pos = nodePos(n); const role = (n.roles || [])[0] || "relay"; const col = ROLE_COLOR[role] || "#64748b";
        const online = n.status === "online";
        ctx.beginPath(); ctx.arc(pos[0], pos[1], 13, 0, 7);
        ctx.fillStyle = online ? "rgba(59,130,246,.08)" : "rgba(51,65,85,.05)"; ctx.fill();
        ctx.shadowColor = col; ctx.shadowBlur = online ? 16 : 0;
        ctx.fillStyle = online ? col : "#334155";
        ctx.beginPath(); ctx.arc(pos[0], pos[1], 7, 0, 7); ctx.fill(); ctx.shadowBlur = 0;
        ctx.lineWidth = 2; ctx.strokeStyle = "rgba(255,255,255,.85)"; ctx.stroke();
        ctx.font = "600 11px -apple-system,system-ui,sans-serif"; ctx.textAlign = "center";
        const label = n.name || n.id;
        const tw = ctx.measureText(label).width;
        ctx.fillStyle = "rgba(10,16,28,.78)";
        ctx.fillRect(pos[0] - tw / 2 - 5, pos[1] - 26, tw + 10, 16);
        ctx.fillStyle = "#e2e8f0"; ctx.fillText(label, pos[0], pos[1] - 14);
      });
    }
    return { init: init, resize: resize, setTopology: setTopology, addPulse: addPulse, addFlow: addFlow, setFlows: setFlows };
  })();
  function showNodeInfo(n) { nodeDetail(n.id, n); }
  function nodeDetail(id, fallback) {
    api("/nodes/" + id + "/detail")
      .done(function (d) { renderNodeDrawer(d); })
      .fail(function () { if (fallback) renderNodeBasic(fallback); else toast("Failed to load node", "bad"); });
  }
  function nodeActions(id, name) {
    return '<div class="flex gap mt"><button class="btn sm" onclick="Fabric.pairNode(\'' + id + "','" + esc(name) + '\')">Pair</button>' +
      '<button class="btn sm ghost" onclick="Fabric.configureNode(\'' + id + '\')">Configure</button>' +
      '<button class="btn sm ghost" onclick="Fabric.viewNodeConfig(\'' + id + '\')">Config</button>' +
      '<button class="btn sm ghost" onclick="Fabric.updateNode(\'' + id + "','" + esc(name) + '\')">Update</button></div>';
  }
  function renderNodeBasic(n) {
    const roles = (n.roles || []).map(function (r) { return pill(ROLE_LABEL[r] || r, "role"); }).join(" ");
    const rows = kv("Region", n.region) + kv("Status", n.status) + kv("Fabric addr", n.fabric_addr) +
      kv("Public endpoint", n.public_endpoint) + kv("Version", n.version) +
      kv("Endpoint pool", n.endpoint_pool_cidr) + kv("Private routes", (n.private_routes || []).join(", "));
    openDrawer(
      '<div class="modal-head"><h2>' + esc(n.name) + '</h2><span class="close-x" onclick="Fabric.closeDrawer()">&times;</span></div>' +
      '<div class="modal-body"><div>' + roles + '</div><h3 style="font-size:13px;margin-top:14px">Node</h3><div class="kvgrid">' + rows + "</div>" +
      nodeActions(n.id, n.name) + "</div>"
    );
  }
  function renderNodeDrawer(d) {
    const n = d.node || {}; const h = n.health || {}; const t = d.totals || {};
    const roles = (n.roles || []).map(function (r) { return pill(ROLE_LABEL[r] || r, "role"); }).join(" ");
    const info = kv("Region", n.region) + kv("Status", n.status) + kv("Fabric addr", n.fabric_addr) +
      kv("Public endpoint", n.public_endpoint) + kv("Hostname", n.hostname) + kv("Version", n.version) +
      kv("Last seen", n.last_seen ? timeAgo(n.last_seen) : "never") +
      kv("Endpoint pool", n.endpoint_pool_cidr) + kv("Private routes", (n.private_routes || []).join(", ")) +
      kv("Egress IPs", (n.egress_ip_pool || []).join(", "));
    const healthRows = Object.keys(h).map(function (k) {
      const v = (typeof h[k] === "object") ? JSON.stringify(h[k]) : h[k];
      return kv(k, v);
    }).join("");
    const totalsRow = kv("Received (24h)", fmtBytes(t.rx_bytes)) + kv("Sent (24h)", fmtBytes(t.tx_bytes)) + kv("Flows (24h)", t.flows_24h);
    const linksHtml = (d.links || []).length ? d.links.map(function (l) {
      return "<tr><td><strong>" + esc(l.peer_name) + "</strong></td>" +
        "<td>" + pill(l.status, l.status) + "</td>" +
        "<td class='muted'>" + (l.latency_ms != null ? l.latency_ms + " ms" : "&mdash;") + "</td>" +
        "<td class='muted'>" + (l.loss_pct != null ? l.loss_pct + "%" : "&mdash;") + "</td>" +
        "<td class='mono'>" + fmtBytes((l.tx_bytes || 0) + (l.rx_bytes || 0)) + "</td></tr>";
    }).join("") : "<tr><td colspan='5' class='empty'>No links</td></tr>";
    const epsHtml = (d.endpoints || []).map(function (e) {
      return "<tr class='clickable' onclick=\"Fabric.endpointDetail('" + e.id + "')\"><td><strong>" + esc(e.name) + "</strong></td>" +
        "<td class='muted'>" + (esc(e.user) || "&mdash;") + "</td>" +
        "<td>" + (e.connected ? pill("connected", "allow") : pill("offline", "")) + "</td>" +
        "<td class='mono muted'>" + (esc(e.address) || "&mdash;") + "</td>" +
        "<td class='mono'>" + fmtBytes((e.rx_bytes || 0) + (e.tx_bytes || 0)) + "</td></tr>";
    }).join("");
    const epsSection = epsHtml ? ('<h3 style="font-size:13px;margin-top:16px">Attached endpoints</h3><table class="data compact"><tbody>' + epsHtml + "</tbody></table>") : "";
    const flowsHtml = (d.flows || []).length ? d.flows.map(function (f) {
      return "<tr><td class='mono muted'>" + hhmmss(f.ts) + "</td>" +
        "<td>" + esc(f.domain || f.sni || f.dst_ip) + "</td>" +
        "<td>" + (f.category ? pill(f.category, "") : "<span class='muted'>&mdash;</span>") + "</td>" +
        "<td class='mono'>" + fmtBytes((f.tx_bytes || 0) + (f.rx_bytes || 0)) + "</td></tr>";
    }).join("") : "<tr><td colspan='4' class='empty'>No recent flows</td></tr>";
    const healthSection = healthRows ? ('<h3 style="font-size:13px;margin-top:16px">Health</h3><div class="kvgrid">' + healthRows + "</div>") : "";
    openDrawer(
      '<div class="modal-head"><h2>' + esc(n.name) + '</h2><span class="close-x" onclick="Fabric.closeDrawer()">&times;</span></div>' +
      '<div class="modal-body"><div>' + roles + "</div>" +
      '<h3 style="font-size:13px;margin-top:14px">Node</h3><div class="kvgrid">' + info + "</div>" +
      healthSection +
      '<h3 style="font-size:13px;margin-top:16px">Traffic</h3><div class="kvgrid">' + totalsRow + "</div>" +
      '<h3 style="font-size:13px;margin-top:16px">Fabric links</h3><table class="data compact"><tbody>' + linksHtml + "</tbody></table>" +
      epsSection +
      '<h3 style="font-size:13px;margin-top:16px">Recent flows</h3><table class="data compact"><tbody>' + flowsHtml + "</tbody></table>" +
      nodeActions(n.id, n.name) + "</div>"
    );
  }

  const MiniTopo = (function () {
    function render(t) {
      const cv = document.getElementById("miniTopo"); if (!cv) return;
      cv.width = cv.clientWidth; cv.height = cv.clientHeight; const ctx = cv.getContext("2d");
      ctx.clearRect(0, 0, cv.width, cv.height);
      const cx = cv.width / 2, cy = cv.height / 2, R = Math.min(cx, cy) - 40;
      const nodes = (t.nodes || []); const n = nodes.length || 1;
      const pos = nodes.map(function (nd, i) { const a = (i / n) * Math.PI * 2 - Math.PI / 2; return [cx + Math.cos(a) * R, cy + Math.sin(a) * R]; });
      (t.links || []).forEach(function (l) {
        const ia = nodes.findIndex(function (x) { return x.id === l.a; }), ib = nodes.findIndex(function (x) { return x.id === l.b; });
        if (ia < 0 || ib < 0) return;
        ctx.strokeStyle = l.status === "up" ? "rgba(34,197,94,.4)" : "rgba(100,116,139,.3)";
        ctx.beginPath(); ctx.moveTo(pos[ia][0], pos[ia][1]); ctx.lineTo(pos[ib][0], pos[ib][1]); ctx.stroke();
      });
      nodes.forEach(function (nd, i) {
        const role = (nd.roles || [])[0] || "relay", col = ROLE_COLOR[role] || "#64748b";
        ctx.fillStyle = nd.status === "online" ? col : "#334155";
        ctx.beginPath(); ctx.arc(pos[i][0], pos[i][1], 8, 0, 7); ctx.fill();
        ctx.fillStyle = "#94a3b8"; ctx.font = "10px sans-serif"; ctx.textAlign = "center";
        ctx.fillText(nd.name, pos[i][0], pos[i][1] - 12);
      });
    }
    return { render: render };
  })();

  // ----------------------------------------------------------------- endpoint drill-down
  function endpointDetail(id) {
    api("/endpoints/" + id + "/detail").done(function (d) {
      const e = d.endpoint || {}; const c = e.conn || {}; const ing = d.ingress; const t = d.totals || {};
      const connState = c.connected ? pill("connected", "allow") : pill("offline", "");
      const connRows = kv("Connected", c.connected ? "yes" : "no") +
        kv("Last handshake", c.last_handshake ? timeAgo(c.last_handshake * 1000) : "never") +
        kv("Remote IP", c.remote_ip) + kv("Received", fmtBytes(c.rx_bytes)) + kv("Sent", fmtBytes(c.tx_bytes)) +
        kv("Overlay addr", e.address) + kv("Public key", e.wg_public_key) + kv("Last seen", e.last_seen ? timeAgo(e.last_seen) : "never");
      const ingRows = ing ? (kv("Ingress node", ing.name) + kv("Region", ing.region) + kv("Ingress status", ing.status) + kv("Endpoint", ing.public_endpoint)) : "";
      const totalsRow = kv("Total received", fmtBytes(t.rx_bytes)) + kv("Total sent", fmtBytes(t.tx_bytes)) + kv("Flows", t.flows);
      const flowsHtml = (d.flows || []).length ? d.flows.map(function (f) {
        return "<tr><td class='mono muted'>" + hhmmss(f.ts) + "</td>" +
          "<td>" + esc(f.domain || f.sni || f.dst_ip) + "<span class='muted'>:" + (f.dst_port || "") + "</span></td>" +
          "<td>" + (f.category ? pill(f.category, "") : "<span class='muted'>&mdash;</span>") + "</td>" +
          "<td>" + pill(f.verdict, f.verdict) + "</td>" +
          "<td class='mono'>" + fmtBytes((f.tx_bytes || 0) + (f.rx_bytes || 0)) + "</td></tr>";
      }).join("") : "<tr><td colspan='5' class='empty'>No flows recorded</td></tr>";
      const dnsHtml = (d.dns || []).length ? d.dns.map(function (r) {
        return "<tr><td class='mono muted'>" + hhmmss(r.ts) + "</td>" +
          "<td>" + esc(r.qname) + "</td><td class='muted'>" + esc(r.qtype) + "</td>" +
          "<td>" + (r.category ? pill(r.category, "") : "<span class='muted'>&mdash;</span>") + "</td>" +
          "<td>" + pill(r.action, "") + "</td></tr>";
      }).join("") : "<tr><td colspan='5' class='empty'>No DNS queries</td></tr>";
      const actHtml = (d.activity || []).length ? d.activity.map(function (a) {
        return "<tr><td class='mono muted'>" + hhmmss(a.ts) + "</td>" +
          "<td><strong>" + esc(a.action) + "</strong></td>" +
          "<td class='muted'>" + (esc(a.actor) || esc(a.actor_type)) + "</td></tr>";
      }).join("") : "<tr><td colspan='3' class='empty'>No activity</td></tr>";
      openDrawer(
        '<div class="modal-head"><h2>Endpoint &middot; ' + esc(e.name) + '</h2><span class="close-x" onclick="Fabric.closeDrawer()">&times;</span></div>' +
        '<div class="modal-body">' +
        '<div>' + connState + " " + pill(e.status, e.status) + " " + (e.inspect_tls ? pill("inspect", "inspect") : pill("bypass", "")) + "</div>" +
        '<h3 style="font-size:13px;margin-top:14px">Connection</h3><div class="kvgrid">' + connRows + ingRows + "</div>" +
        '<h3 style="font-size:13px;margin-top:16px">Traffic totals</h3><div class="kvgrid">' + totalsRow + "</div>" +
        '<h3 style="font-size:13px;margin-top:16px">Recent flows</h3><table class="data compact"><tbody>' + flowsHtml + "</tbody></table>" +
        '<h3 style="font-size:13px;margin-top:16px">Recent DNS</h3><table class="data compact"><tbody>' + dnsHtml + "</tbody></table>" +
        '<h3 style="font-size:13px;margin-top:16px">Activity</h3><table class="data compact"><tbody>' + actHtml + "</tbody></table>" +
        '<div class="flex gap mt"><button class="btn sm primary" onclick="Fabric.endpointConfig(\'' + e.id + '\')">Get config</button>' +
        '<button class="btn sm" onclick="Fabric.editEndpoint(\'' + e.id + '\')">Edit</button>' +
        '<button class="btn sm" onclick="Fabric.shareEndpoint(\'' + e.id + '\')">Share link</button>' +
        '<button class="btn sm danger" onclick="Fabric.revokeEndpoint(\'' + e.id + '\')">Revoke</button>' +
        '<button class="btn sm danger" onclick="Fabric.deleteEndpoint(\'' + e.id + '\')">Delete</button></div>' +
        "</div>"
      );
    }).fail(function () { toast("Could not load endpoint detail", "bad"); });
  }

  // ----------------------------------------------------------------- activity log
  let _actTimer = null;
  function debouncedActivity() { clearTimeout(_actTimer); _actTimer = setTimeout(loadActivity, 300); }
  function activityRow(a) {
    const detail = (a.detail && Object.keys(a.detail).length) ? esc(JSON.stringify(a.detail)) : "";
    const when = a.ts ? new Date(a.ts).toLocaleString() : "";
    return "<tr><td class='mono muted'>" + esc(when) + "</td>" +
      "<td>" + (esc(a.actor) || "&mdash;") + "</td>" +
      "<td>" + pill(a.actor_type || "?", "") + "</td>" +
      "<td><strong>" + esc(a.action) + "</strong></td>" +
      "<td class='mono muted'>" + (esc(a.target) || "&mdash;") + "</td>" +
      "<td class='muted' style='max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'>" + detail + "</td></tr>";
  }
  function loadActivity() {
    const at = $("#activityActorFilter").val() || "";
    const q = ($("#activitySearch").val() || "").trim();
    let path = "/logs?limit=300";
    if (at) path += "&actor_type=" + encodeURIComponent(at);
    if (q) path += "&q=" + encodeURIComponent(q);
    api(path).done(function (rows) {
      $("#activityTable tbody").html(rows.map(activityRow).join("") || "<tr><td colspan='6' class='empty'>No activity yet</td></tr>");
    });
  }

  // ----------------------------------------------------------------- websocket
  function connectWS() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(proto + "://" + location.host + "/ws/ui");
    ws.onopen = function () { $("#conn").addClass("live"); $("#connText").text("live"); };
    ws.onclose = function () { $("#conn").removeClass("live"); $("#connText").text("reconnecting&hellip;"); setTimeout(connectWS, 2500); };
    ws.onmessage = function (ev) {
      let msg; try { msg = JSON.parse(ev.data); } catch (e) { return; }
      handleEvent(msg.type, msg.data);
    };
  }
  function handleEvent(type, d) {
    if (type === "flow") {
      pushFeed("flow", "<strong>" + esc(d.domain || d.dst_ip) + "</strong> " + pill(d.verdict, d.verdict), d.verdict === "denied" ? "#ef4444" : "#22c55e");
      if ($("#view-flows").hasClass("active")) { $("#flowsTable tbody").prepend(flowRow(d)); trim("#flowsTable", 200); }
      WorldMap.addFlow(d);
    } else if (type === "dns") {
      pushFeed("dns", "DNS <strong>" + esc(d.qname) + "</strong> " + esc(d.action), "#06b6d4");
      if ($("#view-dns").hasClass("active")) { $("#dnsTable tbody").prepend(dnsRow(d)); trim("#dnsTable", 200); }
    } else if (type === "node.health") {
      pushFeed("node", "Node " + esc(d.node_id) + " &rarr; " + pill(d.status, d.status), "#3b82f6");
      if ($("#view-nodes").hasClass("active")) loadNodes();
    } else if (type === "policy.changed") {
      pushFeed("policy", "Policy updated &mdash; recompiling data-plane hints", "#8b5cf6");
    } else if (type === "endpoint.state") {
      const label = d.status === "active" ? "connected" : d.status;
      pushFeed("endpoint", "Endpoint <strong>" + esc(d.name) + "</strong> " + pill(label, d.status), "#10b981");
      if ($("#view-endpoints").hasClass("active")) loadEndpoints();
    }
  }
  function trim(sel, max) { const t = $(sel + " tbody"); while (t.children().length > max) t.children().last().remove(); }

  // ----------------------------------------------------------------- utilities exposed
  function copy(id) { const t = document.getElementById(id).innerText; navigator.clipboard.writeText(t).then(function () { toast("Copied"); }); }
  function download(name, id) {
    const blob = new Blob([document.getElementById(id).innerText], { type: "text/plain" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = name; a.click();
  }
  function recomputeFabric() { api("/fabric/recompute", { method: "POST" }).done(function (t) { WorldMap.setTopology(t); MiniTopo.render(t); toast("Mesh recomputed", "good"); }); }
  function refreshAll() { loadDashboard(); }

  // ----------------------------------------------------------------- boot
  const LOADERS = { dashboard: loadDashboard, map: function () { api("/fabric/topology").done(WorldMap.setTopology); }, nodes: loadNodes,
    endpoints: loadEndpoints, policies: loadPolicies, flows: loadFlows, dns: loadDns, activity: loadActivity, pki: loadPki };

  $(function () {
    WorldMap.init();
    loadDashboard(); loadNodes(); loadEndpoints();
    connectWS();
    setInterval(loadDashboard, 30000);
    $(window).on("resize", WorldMap.resize);
    document.addEventListener("click", closeMenus);
  });

  // public namespace
  window.Fabric = {
    closeModal: closeModal, closeDrawer: closeDrawer, refreshAll: refreshAll, recomputeFabric: recomputeFabric,
    openNodeModal: openNodeModal, createNode: createNode, pairNode: pairNode, deleteNode: deleteNode, updateNode: updateNode, viewNodeConfig: viewNodeConfig,
    configureNode: configureNode, saveNodeConfig: saveNodeConfig, nodeDetail: nodeDetail,
    openEndpointModal: openEndpointModal, createEndpoint: createEndpoint, endpointConfig: endpointConfig, revokeEndpoint: revokeEndpoint, shareEndpoint: shareEndpoint, endpointDetail: endpointDetail,
    editEndpoint: editEndpoint, saveEndpointEdit: saveEndpointEdit, deleteEndpoint: deleteEndpoint,
    toggleMenu: toggleMenu, closeMenus: closeMenus,
    openPolicyModal: openPolicyModal, addRule: addRule, removeRule: removeRule, savePolicy: savePolicy, editPolicy: editPolicy, deletePolicy: deletePolicy, toggleAdvanced: toggleAdvanced,
    flowDetail: flowDetail, dnsDetail: dnsDetail, certDetail: certDetail,
    loadActivity: loadActivity, debouncedActivity: debouncedActivity,
    toggleMapFlows: function (on) { WorldMap.setFlows(on); },
    copy: copy, download: download,
  };
})();
