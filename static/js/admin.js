"use strict";

(function () {
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const num = (n) => Number(n || 0).toLocaleString("en-IN");
  const view = $("#view");

  /* ---------- API ---------- */

  class ApiError extends Error {
    constructor(status, message) { super(message); this.status = status; }
  }

  async function api(path, { method = "GET", body } = {}) {
    const res = await fetch(path, {
      method,
      credentials: "same-origin",
      headers: { "X-ScamRead-Admin": "1", ...(body ? { "Content-Type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    if (res.status === 401 && path !== "/admin/api/login") {
      showLogin();
      throw new ApiError(401, "Please log in again.");
    }
    if (!res.ok) {
      const d = data.detail;
      const msg = Array.isArray(d) ? d.map((x) => x.msg).join(", ") : d || "Something went wrong.";
      throw new ApiError(res.status, msg);
    }
    return data;
  }

  let toastTimer;
  function toast(message, isError = false) {
    const t = $("#toast");
    t.textContent = message;
    t.classList.toggle("error", isError);
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.hidden = true; }, isError ? 6000 : 3000);
  }

  async function run(fn, okMessage) {
    try {
      const out = await fn();
      if (okMessage) toast(okMessage);
      return out;
    } catch (e) {
      if (e.status !== 401) toast(e.message || "Something went wrong.", true);
      return null;
    }
  }

  /* ---------- login ---------- */

  function showLogin() {
    $("#boot").hidden = true;
    $("#app-view").hidden = true;
    $("#who").hidden = true;
    $("#login-view").hidden = false;
    setTimeout(() => $("#login-user").focus(), 0);
  }

  function showApp(username) {
    $("#boot").hidden = true;
    $("#login-view").hidden = true;
    $("#app-view").hidden = false;
    $("#who").hidden = false;
    $("#who-name").textContent = username;
    openTab(location.hash.slice(1) || "dashboard");
  }

  $$(".pass-toggle").forEach((b) =>
    b.addEventListener("click", () => {
      const input = document.getElementById(b.dataset.for);
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      b.textContent = show ? "Hide" : "Show";
      b.setAttribute("aria-label", show ? "Hide password" : "Show password");
    })
  );

  $("#login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const err = $("#login-error");
    err.hidden = true;
    const btn = e.target.querySelector("button[type=submit]");
    btn.disabled = true;
    try {
      const data = await api("/admin/api/login", {
        method: "POST",
        body: { username: $("#login-user").value.trim(), password: $("#login-pass").value },
      });
      $("#login-pass").value = "";
      showApp(data.username);
    } catch (ex) {
      err.textContent = ex.message;
      err.hidden = false;
    } finally {
      btn.disabled = false;
    }
  });

  $("#logout").addEventListener("click", async () => {
    await run(() => api("/admin/api/logout", { method: "POST" }));
    showLogin();
  });

  /* ---------- tabs ---------- */

  const TABS = { dashboard: renderDashboard, brands: renderBrands, signs: renderSigns, campaigns: renderCampaigns, account: renderAccount };

  function openTab(name) {
    if (!TABS[name]) name = "dashboard";
    $$(".tab-btn").forEach((b) => (b.dataset.tab === name ? b.setAttribute("aria-current", "page") : b.removeAttribute("aria-current")));
    if (location.hash.slice(1) !== name) history.replaceState(null, "", "#" + name);
    view.innerHTML = `<p class="muted">Loading…</p>`;
    TABS[name]();
  }
  $$(".tab-btn").forEach((b) => b.addEventListener("click", () => openTab(b.dataset.tab)));

  const ACRONYMS = new Set(["sbi", "hdfc", "icici", "axis", "pnb", "bob", "idbi", "yes", "dhl", "usps", "ups", "upi", "kyc", "pan", "lic", "irctc", "bsnl", "jio", "id"]);
  const brandName = (v) => (v ? v.split(" ").map((w) => (ACRONYMS.has(w) ? w.toUpperCase() : w.charAt(0).toUpperCase() + w.slice(1))).join(" ") : "—");
  const shortDay = (iso) => { const d = new Date(iso + "T00:00:00"); return d.toLocaleDateString("en-IN", { day: "numeric", month: "short" }); };
  const sourceBadge = (s) => (s === "seed" ? `<span class="badge">Starter</span>` : s === "private" ? `<span class="badge">Private</span>` : `<span class="badge mine">Added by you</span>`);

  /* ---------- dashboard ---------- */

  async function renderDashboard() {
    const s = await run(() => api("/api/admin/stats?limit=15"));
    if (!s) return;
    const sum = s.summary;
    const max = Math.max(1, ...s.daily.map((d) => d.low + d.medium + d.high));
    const bars = s.daily
      .map((d) => {
        const t = d.low + d.medium + d.high;
        return `<div class="bar" title="${esc(shortDay(d.day))}: ${t} checks (${d.high} high, ${d.medium} medium, ${d.low} low)">
          <i class="low" data-h="${(d.low / max) * 100}"></i><i class="medium" data-h="${(d.medium / max) * 100}"></i><i class="high" data-h="${(d.high / max) * 100}"></i></div>`;
      })
      .join("");
    const labels = s.daily.map((d) => `<span>${esc(shortDay(d.day))}</span>`).join("");

    const rows = (items, cols, empty) =>
      items.length
        ? `<div class="table-wrap"><table><thead><tr>${cols.map((c) => `<th class="${c[2] || ""}">${c[0]}</th>`).join("")}</tr></thead><tbody>${items
            .map((it) => `<tr>${cols.map((c) => `<td class="${c[2] || ""}">${c[1](it)}</td>`).join("")}</tr>`)
            .join("")}</tbody></table></div>`
        : `<div class="table-wrap"><p class="empty">${empty}</p></div>`;

    view.innerHTML = `
      <h2>Dashboard</h2>
      <p class="lead">What the scam checker has seen. Only counts and scam patterns are stored, never people's messages.</p>
      <div class="stats">
        <div class="panel stat"><b>${num(sum.checks_today)}</b><span>Checks today</span></div>
        <div class="panel stat"><b>${num(sum.checks_7_days)}</b><span>Checks, last 7 days</span></div>
        <div class="panel stat hot"><b>${num(sum.risky_7_days)}</b><span>Risky (medium + high), 7 days</span></div>
        <div class="panel stat"><b>${num(sum.scam_websites)}</b><span>Scam websites seen</span></div>
        <div class="panel stat"><b>${num(sum.brands_faked)}</b><span>Brands faked</span></div>
        <div class="panel stat"><b>${num(sum.campaigns_published)}</b><span>Published campaigns</span></div>
      </div>

      <div class="section">
        <h3>Checks per day (last 14 days)</h3>
        <div class="panel chart">
          <div class="bars">${bars}</div>
          <div class="bar-labels">${labels}</div>
          <div class="legend"></div>
        </div>
      </div>

      <div class="grid-2 section">
        <div>
          <h3>Most faked brands</h3>
          ${rows(s.top_brands, [
            ["Brand", (b) => esc(brandName(b.claimed_brand))],
            ["Times", (b) => num(b.hits), "num"],
            ["With fake link", (b) => num(b.with_fake_link), "num"],
          ], "No brand impersonation seen yet.")}
        </div>
        <div>
          <h3>Domain endings in scam links</h3>
          ${rows(s.top_link_endings, [
            ["Ending", (t) => `<code>${esc(t.tld)}</code>`],
            ["Times", (t) => num(t.hits), "num"],
          ], "No scam links seen yet.")}
        </div>
      </div>

      <div class="section">
        <h3>Scam websites seen</h3>
        ${rows(s.top_scam_domains, [
          ["Website", (d) => `<code>${esc(d.domain)}</code>`],
          ["Pretends to be", (d) => esc(brandName(d.claimed_brand))],
          ["Highest score", (d) => num(d.max_risk_score), "num"],
          ["Times", (d) => num(d.hits), "num"],
          ["First seen", (d) => esc(d.first_seen)],
          ["Last seen", (d) => esc(d.last_seen)],
        ], "No scam websites recorded yet. They appear here when people check risky messages with links.")}
        <p class="hint">Tip: group related websites into a campaign (Campaigns tab) so the checker can warn people about them by name.</p>
      </div>`;

    // Legend (built with DOM so no inline styles are needed).
    const legend = $(".legend", view);
    legend.innerHTML = "";
    [["High risk", "var(--red)"], ["Medium", "var(--yel)"], ["Low", "rgba(64,226,214,.55)"]].forEach(([label, color]) => {
      const span = document.createElement("span");
      const dot = document.createElement("i");
      dot.style.background = color;
      span.append(dot, label);
      legend.append(span);
    });
    $$(".bar i", view).forEach((i) => { i.style.height = `${i.dataset.h}%`; });
  }

  /* ---------- brands ---------- */

  async function renderBrands() {
    const p = await run(() => api("/api/admin/patterns"));
    if (!p) return;
    view.innerHTML = `
      <h2>Brands</h2>
      <p class="lead">Companies scammers pretend to be, and their real websites. If a message names a brand but its link goes somewhere else, the checker shows a "fake link" warning.</p>
      <form id="brand-form" class="panel form-card">
        <div class="form-row">
          <div><label class="field-label" for="b-name">Brand name</label><input id="b-name" class="input" placeholder="e.g. Zomato" required></div>
          <div><label class="field-label" for="b-domains">Real websites</label><input id="b-domains" class="input" placeholder="e.g. zomato.com, zoma.to" required></div>
          <div><label class="field-label" for="b-sector">Type</label>
            <select id="b-sector" class="input">
              ${["banking", "payments", "retail", "delivery", "telecom", "government", "technology", "streaming", "messaging", "food", "travel", "other"].map((s) => `<option>${s}</option>`).join("")}
            </select></div>
          <div><button class="btn btn-primary btn-block" type="submit">Add brand</button></div>
        </div>
        <p class="hint">Separate several websites with commas. Sub-websites are covered automatically (zomato.com also covers www.zomato.com).</p>
      </form>
      <div class="section table-wrap">
        <table>
          <thead><tr><th>Brand</th><th>Real websites</th><th>Type</th><th>Source</th><th></th></tr></thead>
          <tbody>${p.brands
            .map(
              (b) => `<tr class="${b.active ? "" : "off"}">
                <td><strong>${esc(brandName(b.name))}</strong></td>
                <td>${b.legit_domains.map((d) => `<code>${esc(d)}</code>`).join(", ")}</td>
                <td>${esc(b.sector || "—")}</td>
                <td>${sourceBadge(b.source)}</td>
                <td class="actions"><button class="btn btn-sm btn-quiet" data-brand="${esc(b.name)}" data-active="${b.active ? 0 : 1}">${b.active ? "Switch off" : "Switch on"}</button></td>
              </tr>`
            )
            .join("")}</tbody>
        </table>
      </div>`;

    $("#brand-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const domains = $("#b-domains").value.split(/[,\s]+/).map((d) => d.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "")).filter(Boolean);
      const ok = await run(
        () => api("/api/admin/patterns/brands", { method: "POST", body: { name: $("#b-name").value.trim(), legit_domains: domains, sector: $("#b-sector").value } }),
        "Brand saved. The checker uses it from now on."
      );
      if (ok) renderBrands();
    });
    $$("button[data-brand]", view).forEach((b) =>
      b.addEventListener("click", async () => {
        const ok = await run(() => api("/api/admin/patterns/active", { method: "POST", body: { kind: "brand", key: b.dataset.brand, active: b.dataset.active === "1" } }), "Updated.");
        if (ok) renderBrands();
      })
    );
  }

  /* ---------- warning signs ---------- */

  const SIGNS = [
    ["urgency", "Pressure words", "Words that rush people, e.g. \"act fast\", \"last chance\".", true],
    ["threat", "Threats", "Scary consequences, e.g. \"account will be frozen\", \"legal action\".", true],
    ["sensitive_request", "Asking for OTP / password", "Requests for secret codes, e.g. \"share the otp\".", true],
    ["financial", "Payment requests", "Money demands, e.g. \"processing fee\", \"pay now\".", true],
    ["kyc", "KYC / verification tricks", "Fake verification, e.g. \"update your pan\".", true],
    ["generic_greeting", "Generic greetings", "e.g. \"dear valued user\".", false],
    ["sensitive_term", "Secret words mentioned", "e.g. \"upi pin\", \"cvv\".", false],
    ["banking_term", "Banking words", "Words that show a banking topic.", false],
    ["delivery_context", "Delivery words", "Words that show a parcel or delivery topic.", false],
    ["delivery_problem", "Delivery problems", "e.g. \"delivery failed\", \"address is incomplete\".", false],
    ["type_investment", "Investment scam words", "e.g. \"guaranteed returns\".", false],
    ["type_job", "Job scam words", "e.g. \"work from home\", \"daily income\".", false],
    ["type_delivery", "Delivery scam words", "Words that mark a delivery scam.", false],
  ];

  function readable(category, value) {
    const isRegex = SIGNS.find((x) => x[0] === category)?.[3];
    if (!isRegex) return { text: value, advanced: false };
    const m = /^\\b(.*)\\b$/.exec(value);
    if (m) {
      const inner = m[1].replace(/\\s\+/g, " ");
      // Plain words: every special character is escaped and there are no \d, \w style codes.
      if (!/(^|[^\\])[()[\]{}|?*+^$.]/.test(inner) && !/\\[a-zA-Z0-9]/.test(inner)) {
        return { text: inner.replace(/\\(.)/g, "$1"), advanced: false };
      }
    }
    return { text: value, advanced: true };
  }

  async function renderSigns() {
    const p = await run(() => api("/api/admin/patterns"));
    if (!p) return;
    const byCat = {};
    p.rules.forEach((r) => (byCat[r.category] = byCat[r.category] || []).push(r));

    const groups = SIGNS.map(([cat, title, help]) => {
      const items = byCat[cat] || [];
      return `<div class="group"><h4>${esc(title)} <span class="muted small">(${items.filter((i) => i.active).length})</span></h4><p>${esc(help)}</p>
        <div class="chips">${items
          .map((r) => {
            const rd = readable(cat, r.value);
            return `<span class="chip ${r.active ? "" : "off"} ${r.source === "analyst" ? "mine" : ""}" title="${esc(r.value)}">${rd.advanced ? `<code>${esc(rd.text)}</code>` : esc(rd.text)}
              <button type="button" data-rule="${r.id}" data-active="${r.active ? 0 : 1}" aria-label="${r.active ? "Turn off" : "Turn on"} ${esc(rd.text)}">${r.active ? "turn off" : "turn on"}</button></span>`;
          })
          .join("") || `<span class="muted small">None yet.</span>`}</div></div>`;
    }).join("");

    view.innerHTML = `
      <h2>Warning signs</h2>
      <p class="lead">Words and phrases the checker looks for. Type normal words; the checker matches them as whole words, in any capital letters. Yellow ones were added by you.</p>
      <form id="sign-form" class="panel form-card">
        <div class="form-row">
          <div><label class="field-label" for="s-cat">Kind of warning sign</label>
            <select id="s-cat" class="input">${SIGNS.map((s) => `<option value="${s[0]}">${esc(s[1])}</option>`).join("")}</select></div>
          <div><label class="field-label" for="s-val">Word or phrase</label><input id="s-val" class="input" placeholder="e.g. last chance" required></div>
          <div><button class="btn btn-primary btn-block" type="submit">Add</button></div>
        </div>
        <p id="s-help" class="hint"></p>
        <label class="check" id="s-adv-wrap"><input type="checkbox" id="s-adv"> Advanced: this is a regular expression</label>
      </form>

      <div class="section">
        <h3>Risky domain endings</h3>
        <p class="muted small">Links ending like these get a "suspicious domain" warning.</p>
        <form id="tld-form" class="form-row">
          <div><input id="t-val" class="input" placeholder="e.g. .xyz" required></div>
          <div><button class="btn btn-ghost btn-block" type="submit">Add ending</button></div>
        </form>
        <div class="chips section">${p.suspicious_tlds
          .map((t) => `<span class="chip ${t.active ? "" : "off"} ${t.source === "analyst" ? "mine" : ""}"><code>${esc(t.tld)}</code><button type="button" data-tld="${esc(t.tld)}" data-active="${t.active ? 0 : 1}">${t.active ? "turn off" : "turn on"}</button></span>`)
          .join("")}</div>
      </div>

      <div class="section"><h3>All warning signs</h3>${groups}</div>`;

    const cat = $("#s-cat");
    const syncHelp = () => {
      const s = SIGNS.find((x) => x[0] === cat.value);
      $("#s-help").textContent = s[2];
      $("#s-adv-wrap").hidden = !s[3];
      if (!s[3]) $("#s-adv").checked = false;
    };
    cat.addEventListener("change", syncHelp);
    syncHelp();

    $("#sign-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const ok = await run(
        () => api("/api/admin/patterns/rules", { method: "POST", body: { category: cat.value, value: $("#s-val").value, plain: !$("#s-adv").checked } }),
        "Added. The checker uses it from now on."
      );
      if (ok) renderSigns();
    });
    $("#tld-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const ok = await run(() => api("/api/admin/patterns/tlds", { method: "POST", body: { tld: $("#t-val").value } }), "Ending added.");
      if (ok) renderSigns();
    });
    $$("button[data-rule]", view).forEach((b) =>
      b.addEventListener("click", async () => {
        const ok = await run(() => api("/api/admin/patterns/active", { method: "POST", body: { kind: "rule", key: b.dataset.rule, active: b.dataset.active === "1" } }), "Updated.");
        if (ok) renderSigns();
      })
    );
    $$("button[data-tld]", view).forEach((b) =>
      b.addEventListener("click", async () => {
        const ok = await run(() => api("/api/admin/patterns/active", { method: "POST", body: { kind: "tld", key: b.dataset.tld, active: b.dataset.active === "1" } }), "Updated.");
        if (ok) renderSigns();
      })
    );
  }

  /* ---------- campaigns ---------- */

  const IND_TYPES = [
    ["domain", "Website (e.g. sbi-kyc.tk)"],
    ["url", "Full link"],
    ["phone_number", "Phone number"],
    ["email_address", "Email address"],
    ["bitcoin_wallet", "Bitcoin wallet"],
    ["ethereum_wallet", "Ethereum wallet"],
    ["ipv4_address", "IP address"],
  ];
  const indLabel = (t) => (IND_TYPES.find((x) => x[0] === t) || [t, t])[1].replace(/ \(.*\)$/, "");

  async function renderCampaigns(openId) {
    const data = await run(() => api("/api/admin/campaigns"));
    if (!data) return;
    view.innerHTML = `
      <h2>Campaigns</h2>
      <p class="lead">A campaign is a group of scam messages from the same gang, e.g. "Fake SBI KYC texts, Nov 2026". Add their websites, numbers or wallets. Once you publish a campaign, anyone who checks a message containing one of them sees <strong>"Known scam campaign"</strong> with your title.</p>

      <form id="camp-form" class="panel form-card">
        <div class="form-row">
          <div><label class="field-label" for="c-title">Title</label><input id="c-title" class="input" placeholder="e.g. Fake SBI KYC texts (Nov 2026)" required></div>
          <div><label class="field-label" for="c-brand">Pretends to be</label><input id="c-brand" class="input" placeholder="e.g. SBI"></div>
          <div><label class="field-label" for="c-type">Scam type</label>
            <select id="c-type" class="input">${["Bank / KYC", "Delivery", "Job", "Investment / crypto", "OTP / account takeover", "Prize / lottery", "Loan / app", "Other"].map((t) => `<option>${t}</option>`).join("")}</select></div>
        </div>
        <div class="form-row section">
          <div><label class="field-label" for="c-summary">Short description (shown to the public)</label><textarea id="c-summary" class="input" maxlength="2000" placeholder="e.g. SMS saying your SBI account will be blocked unless you update KYC at a fake website."></textarea></div>
        </div>
        <div class="form-row"><div><label class="field-label" for="c-countries">Countries</label><input id="c-countries" class="input" placeholder="e.g. India"></div>
        <div><button class="btn btn-primary btn-block" type="submit">Create campaign (as draft)</button></div></div>
      </form>

      <div class="section camp-list">${data.campaigns.length ? data.campaigns
        .map((c) => `<div class="panel camp"><div><h4>${esc(c.title)}</h4><p>${c.review_status === "published" ? `<span class="badge pub">Published</span>` : `<span class="badge">Draft</span>`} · ${num(c.indicator_count)} item(s)${c.impersonated_brand ? ` · pretends to be ${esc(c.impersonated_brand)}` : ""}${c.threat_type ? ` · ${esc(c.threat_type)}` : ""}</p></div>
          <button class="btn btn-sm btn-ghost" data-open="${esc(c.campaign_id)}">Open</button></div>`)
        .join("") : `<div class="table-wrap"><p class="empty">No campaigns yet. Create the first one above.</p></div>`}</div>
      <div id="camp-detail"></div>`;

    $("#camp-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const out = await run(
        () => api("/api/admin/campaigns", {
          method: "POST",
          body: {
            title: $("#c-title").value.trim(),
            impersonated_brand: $("#c-brand").value.trim() || null,
            threat_type: $("#c-type").value,
            summary: $("#c-summary").value.trim() || null,
            countries: $("#c-countries").value.split(",").map((x) => x.trim()).filter(Boolean),
            status: "active",
            review_status: "unreviewed",
          },
        }),
        "Campaign created as a draft. Now add its websites or numbers."
      );
      if (out) renderCampaigns(out.campaign_id);
    });
    $$("button[data-open]", view).forEach((b) => b.addEventListener("click", () => openCampaign(b.dataset.open)));
    if (openId) openCampaign(openId);
  }

  async function openCampaign(id) {
    const d = await run(() => api(`/api/admin/campaigns/${encodeURIComponent(id)}`));
    if (!d) return;
    const c = d.campaign;
    const published = c.review_status === "published";
    const box = $("#camp-detail");
    box.innerHTML = `
      <div class="panel camp-detail">
        <div class="camp-head">
          <div><p class="label">Campaign</p><h3>${esc(c.title)}</h3>
          <p class="muted small">${published ? "Published: the checker warns people about this campaign." : "Draft: not shown to the public yet."}</p></div>
          <button class="btn btn-sm ${published ? "btn-quiet" : "btn-primary"}" id="c-publish">${published ? "Unpublish" : "Publish"}</button>
        </div>
        ${c.summary ? `<p>${esc(c.summary)}</p>` : ""}
        <form id="ind-form" class="form-row section">
          <div><label class="field-label" for="i-type">Add an item</label><select id="i-type" class="input">${IND_TYPES.map((t) => `<option value="${t[0]}">${esc(t[1])}</option>`).join("")}</select></div>
          <div><label class="field-label" for="i-val">Value</label><input id="i-val" class="input" placeholder="e.g. sbi-kyc.tk" required></div>
          <div><button class="btn btn-ghost btn-block" type="submit">Add</button></div>
        </form>
        <div class="table-wrap section">${d.indicators.length ? `<table><thead><tr><th>Kind</th><th>Value</th><th></th></tr></thead><tbody>${d.indicators
          .map((i) => `<tr><td>${esc(indLabel(i.indicator_type))}</td><td><code>${esc(i.indicator_value)}</code></td><td class="actions"><button class="btn btn-sm btn-danger" data-rm-type="${esc(i.indicator_type)}" data-rm-val="${esc(i.indicator_value)}">Remove</button></td></tr>`)
          .join("")}</tbody></table>` : `<p class="empty">No items yet. Add the scam websites, phone numbers or wallets used in this campaign.</p>`}</div>
      </div>`;
    box.scrollIntoView({ behavior: "smooth", block: "start" });

    $("#c-publish").addEventListener("click", async () => {
      const ok = await run(
        () => api(`/api/admin/campaigns/${encodeURIComponent(id)}/review?review_status=${published ? "unreviewed" : "published"}`, { method: "POST" }),
        published ? "Unpublished." : "Published. The checker now warns people about it."
      );
      if (ok) renderCampaigns(id);
    });
    $("#ind-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const ok = await run(
        () => api(`/api/admin/campaigns/${encodeURIComponent(id)}/indicators`, { method: "POST", body: { indicator_type: $("#i-type").value, indicator_value: $("#i-val").value } }),
        "Added."
      );
      if (ok) renderCampaigns(id);
    });
    $$("button[data-rm-type]", box).forEach((b) =>
      b.addEventListener("click", async () => {
        const ok = await run(
          () => api(`/api/admin/campaigns/${encodeURIComponent(id)}/indicators/remove`, { method: "POST", body: { indicator_type: b.dataset.rmType, indicator_value: b.dataset.rmVal } }),
          "Removed."
        );
        if (ok) renderCampaigns(id);
      })
    );
  }

  /* ---------- account ---------- */

  function renderAccount() {
    view.innerHTML = `
      <h2>Account</h2>
      <p class="lead">You are logged in as <strong>${esc($("#who-name").textContent)}</strong>. You stay logged in on this browser for 30 days unless you log out.</p>
      <form id="pw-form" class="panel form-card" autocomplete="off">
        <h3>Change password</h3>
        <div class="form-row">
          <div><label class="field-label" for="pw-cur">Current password</label><input id="pw-cur" class="input" type="password" autocomplete="current-password" required></div>
          <div><label class="field-label" for="pw-new">New password (12+ characters)</label><input id="pw-new" class="input" type="password" autocomplete="new-password" minlength="12" required></div>
          <div><label class="field-label" for="pw-rep">New password again</label><input id="pw-rep" class="input" type="password" autocomplete="new-password" minlength="12" required></div>
        </div>
        <button class="btn btn-primary" type="submit">Change password</button>
        <p class="hint">Changing the password logs out every other browser.</p>
      </form>`;
    $("#pw-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      if ($("#pw-new").value !== $("#pw-rep").value) return toast("The two new passwords are different.", true);
      if ($("#pw-new").value.length < 12) return toast("Use at least 12 characters.", true);
      const ok = await run(
        () => api("/admin/api/password", { method: "POST", body: { current_password: $("#pw-cur").value, new_password: $("#pw-new").value } }),
        "Password changed."
      );
      if (ok) e.target.reset();
    });
  }

  /* ---------- start ---------- */

  api("/admin/api/me")
    .then((me) => showApp(me.username))
    .catch(() => showLogin());
})();
