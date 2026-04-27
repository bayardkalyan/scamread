const input = document.querySelector("#message");
const analyzeButton = document.querySelector("#analyzeButton");
const charCount = document.querySelector("#charCount");
const statusBox = document.querySelector("#status");
const results = document.querySelector("#results");
const riskScore = document.querySelector("#riskScore");
const riskLevel = document.querySelector("#riskLevel");
const scamType = document.querySelector("#scamType");
const redFlags = document.querySelector("#redFlags");
const explanation = document.querySelector("#explanation");
const recommendedAction = document.querySelector("#recommendedAction");

function setStatus(message, isError = false) {
  statusBox.textContent = message;
  statusBox.classList.toggle("error", isError);
}

function updateCount() {
  charCount.textContent = `${input.value.length} / 8000`;
}

function renderAnalysis(data) {
  riskScore.textContent = data.risk_score;
  riskLevel.textContent = data.risk_level;
  riskLevel.className = `badge ${data.risk_level}`;
  scamType.textContent = data.scam_type || "Unknown";

  redFlags.replaceChildren();
  const flags = data.red_flags?.length ? data.red_flags : ["No specific red flags identified."];
  for (const flag of flags) {
    const item = document.createElement("li");
    item.textContent = flag;
    redFlags.appendChild(item);
  }

  explanation.textContent = data.explanation;
  recommendedAction.textContent = data.recommended_action;
  results.classList.remove("hidden");
}

async function analyze() {
  const text = input.value.trim();
  if (!text) {
    setStatus("Paste a message or link first.", true);
    results.classList.add("hidden");
    return;
  }

  analyzeButton.disabled = true;
  setStatus("Analyzing...");

  try {
    const response = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });

    const payload = await response.json();
    if (!response.ok) {
      if (payload && typeof payload.risk_score === "number") {
        renderAnalysis(payload);
      }
      throw new Error(payload.explanation || payload.detail || "Analysis failed.");
    }

    renderAnalysis(payload);
    setStatus("Analysis complete.");
  } catch (error) {
    setStatus(error.message || "Something went wrong.", true);
  } finally {
    analyzeButton.disabled = false;
  }
}

input.addEventListener("input", updateCount);
analyzeButton.addEventListener("click", analyze);
input.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
    analyze();
  }
});

updateCount();
