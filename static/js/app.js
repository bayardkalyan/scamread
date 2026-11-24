"use strict";

(function () {
  const form = document.querySelector("#analysis-form");
  const textArea = document.querySelector("#suspicious-text");
  const analyseButton = document.querySelector("#analyse-button");
  const inputView = document.querySelector("#input-view");
  const resultView = document.querySelector("#result-view");
  const heroHeader = document.querySelector("#hero-header");
  const counter = document.querySelector("#character-count");
  const formError = document.querySelector("#form-error");
  const MAX = 20000;

  const track = (name, params) => {
    if (typeof window.gtag === "function") window.gtag("event", name, params || {});
  };

  const escapeHtml = (value) =>
    String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const titleCase = (value) =>
    String(value).replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase()).replace(/\bUrls\b/, "URLs").replace(/\bIpv4\b/, "IPv4").replace(/\bMd5\b/, "MD5").replace(/\bSha(\d+)\b/, "SHA$1");

  const ACRONYMS = new Set(["sbi", "hdfc", "icici", "axis", "pnb", "bob", "idbi", "yes", "dhl", "usps", "ups", "upi", "kyc", "pan", "lic", "irctc", "bsnl", "jio", "id"]);
  const brandName = (value) =>
    value.split(" ").map((w) => (ACRONYMS.has(w) ? w.toUpperCase() : w.charAt(0).toUpperCase() + w.slice(1))).join(" ");

  /* ---------- views ---------- */

  function showInputView() {
    resultView.hidden = true;
    resultView.innerHTML = "";
    inputView.hidden = false;
    heroHeader.hidden = false;
    textArea.value = "";
    updateCount();
    textArea.focus();
  }

  function showResultView() {
    inputView.hidden = true;
    heroHeader.hidden = true;
    resultView.hidden = false;
    window.scrollTo({ top: 0, behavior: "smooth" });
    resultView.focus({ preventScroll: true });
  }

  function setLoading(isLoading) {
    analyseButton.setAttribute("aria-busy", String(isLoading));
    analyseButton.disabled = isLoading;
    analyseButton.querySelector(".button-label").textContent = isLoading ? "Checking…" : "Check this message";
  }

  function showError(message) {
    formError.textContent = message;
    formError.hidden = !message;
  }

  function updateCount() {
    counter.textContent = `${textArea.value.length} / ${MAX}`;
  }

  textArea.addEventListener("input", () => {
    updateCount();
    if (!formError.hidden) showError("");
  });
  textArea.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) form.requestSubmit();
  });
  updateCount();

  /* ---------- report ---------- */

  const VERDICTS = {
    high: ["Very likely a scam", "This message uses several tricks scammers rely on. Do not reply, click or pay."],
    medium: ["Be careful: this looks suspicious", "Some warning signs are present. Check with the sender through an official channel before you act."],
    low: ["No strong scam signs found", "We didn't find common scam tricks. Scams change fast, so still stay alert."],
  };

  function pressureWord(score) {
    if (score >= 60) return "High";
    if (score >= 25) return "Medium";
    if (score > 0) return "Low";
    return "None";
  }

  function adviceFor(level) {
    const items = [
      "Don't click the link or call numbers given in the message.",
      "Never share an OTP, PIN, password or card details. Real banks and companies never ask for them.",
      "Contact the company yourself, using the website or app you already trust.",
    ];
    if (level !== "low") {
      items.push(
        'Already paid or shared details? Call <strong>1930</strong> (India cybercrime helpline) or report at <a href="https://cybercrime.gov.in/" rel="noopener">cybercrime.gov.in</a> right away.'
      );
    }
    return items.map((item) => `<li>${item}</li>`).join("");
  }

  function renderReport(data) {
    const a = data.analysis;
    const level = ["high", "medium", "low"].includes(a.risk_level) ? a.risk_level : "low";
    const [headline, sub] = VERDICTS[level];
    const urgency = Number(a.urgency_score || 0);
    const links = (a.link_domains || []).length;

    track("analysis_completed", { risk_level: a.risk_level, risk_score: a.risk_score });

    const realFlags = a.red_flags.filter((f) => f !== "No obvious suspicious patterns detected");
    const flagsHtml = realFlags.length
      ? realFlags.map((f) => `<li>${escapeHtml(f)}</li>`).join("")
      : `<li class="ok">No obvious scam patterns detected.</li>`;

    const typesHtml = a.suspected_types.length
      ? a.suspected_types.map((t) => `<span class="tag">${escapeHtml(titleCase(t))}</span>`).join("")
      : `<span class="muted">No specific scam type identified.</span>`;

    const groups = Object.entries(data.indicators)
      .filter(([, values]) => values.length)
      .map(
        ([type, values]) => `
        <div class="indicator-group">
          <h4>${escapeHtml(titleCase(type))}</h4>
          <ul>${values.map((v) => `<li><code>${escapeHtml(v)}</code></li>`).join("")}</ul>
        </div>`
      );
    const indicatorsHtml = groups.length ? `<div class="indicators">${groups.join("")}</div>` : `<p class="muted">No links, numbers or other details were found.</p>`;

    let callout = "";
    if (a.brand_mismatch && a.claimed_brand) {
      const fake = (a.link_domains || []).filter(
        (d) => !(a.official_domains || []).some((o) => d === o || d.endsWith("." + o))
      );
      callout = `
        <div class="callout">
          <strong>Fake link warning.</strong>
          This message mentions <strong>${escapeHtml(brandName(a.claimed_brand))}</strong>, but the link goes to
          ${fake.slice(0, 3).map((d) => `<code>${escapeHtml(d)}</code>`).join(", ") || "another website"}.
          ${a.official_domains && a.official_domains.length ? `The official website is <code>${escapeHtml(a.official_domains[0])}</code>.` : ""}
        </div>`;
    }

    let campaignHtml = "";
    if (data.campaign && data.campaign.matched && data.campaign.campaign) {
      const c = data.campaign.campaign.campaign || {};
      campaignHtml = `
        <div class="campaign">
          <strong>Known scam campaign:</strong> ${escapeHtml(c.title || "")}
          ${c.summary ? `<p class="muted campaign-summary">${escapeHtml(c.summary)}</p>` : ""}
        </div>`;
    }

    resultView.innerHTML = `
      <div class="scam-report">
        <div class="verdict risk-${level}">
          <div class="verdict-top">
            <div>
              <p class="verdict-kicker">${escapeHtml(level)} risk</p>
              <h2>${headline}</h2>
              <p class="verdict-sub">${sub}</p>
            </div>
            <div class="score" aria-label="Risk score ${escapeHtml(a.risk_score)} out of 100">
              <strong>${escapeHtml(a.risk_score)}</strong><span>/ 100</span>
            </div>
          </div>
          <div class="meter" aria-hidden="true"><i data-w="${Number(a.risk_score) || 0}"></i></div>
        </div>

        <div class="facts">
          <div class="fact">
            <p class="fact-label">Pretends to be</p>
            <p class="fact-value">${a.claimed_brand ? escapeHtml(brandName(a.claimed_brand)) : "No known brand"}</p>
          </div>
          <div class="fact">
            <p class="fact-label">Pressure level</p>
            <p class="fact-value">${pressureWord(urgency)}</p>
            <div class="meter" aria-hidden="true"><i data-w="${urgency}"></i></div>
          </div>
          <div class="fact">
            <p class="fact-label">Links found</p>
            <p class="fact-value">${links}</p>
          </div>
        </div>

        ${callout}
        ${campaignHtml}

        <div class="report-section">
          <h3>Why it looks suspicious</h3>
          <ul class="flags">${flagsHtml}</ul>
        </div>

        <div class="report-section">
          <h3>Possible scam type</h3>
          <div class="tags">${typesHtml}</div>
        </div>

        <div class="report-section">
          <h3>What we found in the message</h3>
          ${indicatorsHtml}
        </div>

        <div class="report-section">
          <h3>What you should do</h3>
          <ul class="advice">${adviceFor(level)}</ul>
        </div>

        <div class="report-actions">
          <button type="button" id="check-another-button" class="btn btn-primary">Check another message</button>
          <a class="btn btn-ghost" href="https://scamread.com/learn/">Learn to spot scams</a>
        </div>

        <p class="disclaimer">ScamRead gives an automatic, rule-based risk check. It can't guarantee that a message is safe or a scam. Your message was checked in memory and not saved.</p>
      </div>`;

    showResultView();
    requestAnimationFrame(() =>
      resultView.querySelectorAll(".meter > i").forEach((bar) => {
        bar.style.width = `${Math.max(0, Math.min(100, Number(bar.dataset.w)))}%`;
      })
    );

    resultView.querySelector("#check-another-button").addEventListener("click", () => {
      track("check_another");
      showInputView();
    });
  }

  /* ---------- submit ---------- */

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const text = textArea.value.trim();
    if (!text) {
      showError("Paste a message or link first.");
      textArea.focus();
      return;
    }
    showError("");
    track("analysis_started");
    setLoading(true);

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        const detail = Array.isArray(data.detail) ? data.detail[0] && data.detail[0].msg : data.detail;
        throw new Error(detail || "Analysis failed.");
      }
      renderReport(data);
    } catch (error) {
      console.error("ScamRead error:", error);
      showError("We couldn't check the message right now. Please try again in a moment.");
    } finally {
      setLoading(false);
    }
  });
})();
