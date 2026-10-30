const $ = (id) => document.getElementById(id);
let lastCiphertext = "";

function setText(id, value) {
  $(id).textContent = value ?? "--";
}

function renderProbabilities(probabilities = {}) {
  const root = $("probabilities");
  root.replaceChildren();
  const order = ["AES-128", "ASCON-128", "GIFT-64"];
  order.forEach((name) => {
    const value = Number(probabilities[name] ?? 0);
    const row = document.createElement("div");
    row.className = "probability-row";

    const label = document.createElement("span");
    label.className = "probability-label";
    label.textContent = name;

    const track = document.createElement("div");
    track.className = "bar-track";
    const fill = document.createElement("div");
    fill.className = "bar-fill";
    fill.style.width = `${Math.max(0, Math.min(100, value))}%`;
    track.appendChild(fill);

    const number = document.createElement("strong");
    number.textContent = `${value.toFixed(2)}%`;

    row.append(label, track, number);
    root.appendChild(row);
  });
}

function renderHistory(history = []) {
  const root = $("history");
  root.replaceChildren();
  if (!history.length) {
    const empty = document.createElement("span");
    empty.className = "muted";
    empty.textContent = "No events yet";
    root.appendChild(empty);
    return;
  }

  history.forEach((item, index) => {
    if (index > 0) {
      const arrow = document.createElement("span");
      arrow.className = "history-arrow";
      arrow.textContent = "→";
      root.appendChild(arrow);
    }
    const chip = document.createElement("div");
    chip.className = "history-chip";
    const algorithm = document.createElement("strong");
    algorithm.textContent = item.algorithm;
    const scenario = document.createElement("small");
    scenario.textContent = item.scenario || "";
    chip.append(algorithm, scenario);
    root.appendChild(chip);
  });
}

function render(data) {
  setText("battery", data.battery);
  setText("cpu", data.cpu_usage);
  setText("memory", data.memory_usage);
  setText("latency", data.latency);
  setText("packetLoss", data.packet_loss);
  setText("threat", data.threat_level);
  setText("sensitivity", data.data_sensitivity);
  setText("scenarioText", data.scenario);
  setText("scenarioBadge", data.scenario);
  setText("algorithm", data.algorithm);
  setText("confidence", `${Number(data.confidence).toFixed(2)}%`);
  renderProbabilities(data.probabilities);
  renderHistory(data.history);

  setText("switchNote", `Latest event: ${data.switch || "—"}`);
  setText("plaintext", data.plaintext);
  lastCiphertext = data.ciphertext || "";
  setText("ciphertext", lastCiphertext || "No ciphertext returned");
  setText("encryptionStatus", data.encryption_success ? "SUCCESS" : "FAILED");
  setText("decryptionStatus", data.decryption_success ? "SUCCESS" : "FAILED");
  setText("matchStatus", data.message_match ? "MATCH" : "MISMATCH");
  $("encryptionStatus").className = data.encryption_success ? "good" : "bad";
  $("decryptionStatus").className = data.decryption_success ? "good" : "bad";
  $("matchStatus").className = data.message_match ? "good" : "bad";

  setText("encryptionTime", Number(data.encryption_ms).toFixed(4));
  setText("decryptionTime", Number(data.decryption_ms).toFixed(4));
  setText("roundTrip", data.message_match ? "PASS" : "FAIL");
  $("roundTrip").className = data.message_match ? "good" : "bad";
  setText("pipelineAlgorithm", data.algorithm);
  setText("pipelineStatus", data.message_match
    ? "✓ ENCRYPTION + ROUND-TRIP VERIFICATION PASSED"
    : "⚠ VERIFICATION FAILED");
  $("pipelineStatus").className = data.message_match ? "success-line" : "error-line";
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

async function loadStatus() {
  try {
    render(await requestJson("/api/status"));
  } catch (error) {
    setText("actionMessage", `Could not load dashboard: ${error.message}`);
  }
}

async function runAction(url, message) {
  const nextButton = $("nextScenario");
  nextButton.disabled = true;
  $("reset").disabled = true;
  setText("actionMessage", message);
  try {
    render(await requestJson(url, { method: "POST" }));
    setText("actionMessage", "Updated successfully");
  } catch (error) {
    setText("actionMessage", `Error: ${error.message}`);
  } finally {
    nextButton.disabled = false;
    $("reset").disabled = false;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  loadStatus();
  $("nextScenario").addEventListener("click", () => runAction("/api/next", "Running next scenario…"));
  $("reset").addEventListener("click", () => runAction("/api/reset", "Resetting demo…"));
  $("copyCiphertext").addEventListener("click", async () => {
    if (!lastCiphertext) return setText("actionMessage", "No ciphertext to copy");
    try {
      await navigator.clipboard.writeText(lastCiphertext);
      setText("actionMessage", "Ciphertext copied");
    } catch {
      setText("actionMessage", "Clipboard access unavailable in this browser");
    }
  });
});
