"use strict";

const form = document.querySelector("#analysis-form");
const textArea = document.querySelector("#suspicious-text");
const analyseButton = document.querySelector("#analyse-button");

const inputView = document.querySelector("#input-view");
const resultView = document.querySelector("#result-view");
const heroHeader = document.querySelector("#hero-header");

/* -------------------------
   VIEW MANAGEMENT
------------------------- */

function showInputView() {
  resultView.hidden = true;
  inputView.hidden = false;
  heroHeader.hidden = false;

  textArea.value = "";
  updateCharacterCount();

  textArea.focus();
}


function showResultView() {
 inputView.hidden = true;
  resultView.hidden = false;
  heroHeader.hidden = true;
}


/* -------------------------
   LOADING STATE
------------------------- */

function setLoading(isLoading) {
  analyseButton.setAttribute("aria-busy", String(isLoading));
  analyseButton.disabled = isLoading;
}


/* -------------------------
   CHARACTER COUNT
------------------------- */

function updateCharacterCount() {
  const count = textArea.value.length;
  const counter = document.querySelector("#character-count");

  counter.textContent = `${count} / 20000`;
}

textArea.addEventListener("input", updateCharacterCount);

updateCharacterCount();


/* -------------------------
   HTML SAFETY
------------------------- */

function escapeHtml(value) {
  const div = document.createElement("div");

  div.textContent = value ?? "";

  return div.innerHTML;
}


/* -------------------------
   REPORT RENDERING
------------------------- */

function renderReport(data) {
  const analysis = data.analysis;
  const indicators = data.indicators;

   // GA4: analysis completed successfully
  if (typeof gtag === "function") {
    gtag("event", "analysis_completed", {
      risk_level: analysis.risk_level,
      risk_score: analysis.risk_score
    });
  }

  /* Red flags */

  const redFlags = analysis.red_flags.length
    ? analysis.red_flags
        .map((flag) => `<li>${escapeHtml(flag)}</li>`)
        .join("")
    : `<li>No obvious scam patterns detected.</li>`;


  /* Suspected scam types */

 const suspectedTypes = analysis.suspected_types.length
  ? analysis.suspected_types
      .map(type => {
        const readableType = type
    .replace(/_/g, " ")
    .replace(/\b\w/g, letter => letter.toUpperCase())
    .replace(/^Urls$/, "URLs");

        return `<span class="report-tag">${escapeHtml(readableType)}</span>`;
      })
      .join("")
  : `<span class="report-muted">No specific scam type identified</span>`;


  /* Technical indicators */

  const indicatorSections = [];

  for (const [type, values] of Object.entries(indicators)) {

    if (!values.length) {
      continue;
    }

    const readableType = type
      .replace(/_/g, " ")
      .replace(/\b\w/g, (letter) => letter.toUpperCase());

    const items = values
      .map(
        (value) =>
          `<li><code>${escapeHtml(value)}</code></li>`
      )
      .join("");

    indicatorSections.push(`
      <div class="indicator-group">

        <h4>
          ${escapeHtml(readableType)}
        </h4>

        <ul>
          ${items}
        </ul>

      </div>
    `);
  }


  const indicatorsHtml = indicatorSections.length
    ? indicatorSections.join("")
    : `
      <p class="report-muted">
        No technical indicators were detected.
      </p>
    `;


  /* Risk class */

  const riskClass =
    `risk-${analysis.risk_level.toLowerCase()}`;


  /* Build report */

  resultView.innerHTML = `

    <div class="scam-report">


      <!-- Header -->

      <div class="report-header">

        <p class="report-label">
          ScamRead Analysis
        </p>

        <div class="risk-result ${riskClass}">

          <div>

            <span class="risk-label">Risk level</span>
<strong>${escapeHtml(analysis.risk_level.toUpperCase())} RISK</strong>

          </div>


          <div class="risk-score">
            ${escapeHtml(analysis.risk_score)}/100
          </div>

        </div>

      </div>


      <!-- Red flags -->

      <div class="report-section">

        <h3>
          Why does this look suspicious?
        </h3>

        <ul class="red-flags">
          ${redFlags}
        </ul>

      </div>


      <!-- Scam type -->

      <div class="report-section">

        <h3>
          Possible scam type
        </h3>

        <div class="report-tags">
          ${suspectedTypes}
        </div>

      </div>


      <!-- Indicators -->

      <div class="report-section">

        <h3>
          Indicators detected
        </h3>

        ${indicatorsHtml}

      </div>


      <!-- Advice -->

      <div class="report-section report-advice">

        <h3>
          What should you do?
        </h3>

        <p>
          Do not click suspicious links, share passwords or OTPs,
          or send money until you independently verify the request
          through an official channel.
        </p>

      </div>


      <!-- CTA -->

      <div class="report-actions">

        <button
          type="button"
          id="check-another-button"
        >
          Check Another Message
        </button>

        <a href="https://scamread.com/blog">
          Read Scam Guides
        </a>

      </div>


      <!-- Disclaimer -->

      <p class="report-disclaimer">

        ScamRead provides a rule-based risk assessment.
        It does not guarantee that a message is legitimate
        or fraudulent.

      </p>


    </div>
  `;


  /* Switch from input → result */

  showResultView();


  /* Check another message */

  const checkAnotherButton =
    document.querySelector("#check-another-button");

  if (checkAnotherButton) {
  checkAnotherButton.addEventListener("click", () => {
    if (typeof gtag === "function") {
      gtag("event", "check_another");
    }

    showInputView();
  });
}
}


/* -------------------------
   FORM SUBMISSION
------------------------- */

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const text = textArea.value.trim();

  if (!text) {
    alert("Please paste a suspicious message before analysing.");
    textArea.focus();
    return;
  }

  // GA4: user started an analysis
  if (typeof gtag === "function") {
    gtag("event", "analysis_started");
  }

  setLoading(true);


    try {

      const response = await fetch(
        "/api/analyze",
        {
          method: "POST",

          headers: {
            "Content-Type": "application/json"
          },

          body: JSON.stringify({
            text: text
          })
        }
      );


      const data = await response.json();


      if (!response.ok) {

        throw new Error(
          data.detail || "Analysis failed."
        );

      }


      renderReport(data);

    }


    catch (error) {

      console.error(
        "ScamRead error:",
        error
      );

      alert(
        "We couldn't analyse the message right now. Please try again."
      );

    }


    finally {

      setLoading(false);

    }

  }
);