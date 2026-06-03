// ============================================================
// KQL Detection Assistant — Validation Logic
// Pure vanilla JS, no dependencies.
// ============================================================

// ── Schema ──────────────────────────────────────────────────

// Tables that are valid for v1.
const KNOWN_TABLES = ["DeviceProcessEvents", "DeviceFileEvents"];

// Fields that exist on each table.
const TABLE_FIELDS = {
  DeviceProcessEvents: [
    "Timestamp", "DeviceName", "AccountName",
    "InitiatingProcessFileName", "FileName",
    "ProcessCommandLine", "InitiatingProcessCommandLine",
    "FolderPath", "SHA256", "InitiatingProcessSHA256"
  ],
  DeviceFileEvents: [
    "Timestamp", "DeviceName", "AccountName", "ActionType",
    "FolderPath", "FileName", "InitiatingProcessFileName",
    "InitiatingProcessCommandLine", "SHA256"
  ]
};

// Fields that do NOT exist but analysts sometimes hallucinate.
const INVALID_FIELDS = {
  DeviceProcessEvents: ["ParentProcess", "ChildProcess", "ParentProcessName", "ChildProcessName"],
  DeviceFileEvents:    ["ParentProcess", "ChildProcess", "ParentProcessName", "ChildProcessName"]
};

// Markdown headings the package must contain.
const REQUIRED_SECTIONS = [
  "Detection Goal",
  "Required Data Source",
  "Required Table",
  "Required Fields",
  "KQL Query",
  "Why This Query Works",
  "False Positives",
  "Tuning Ideas",
  "What This Query Cannot Prove",
  "MITRE ATT&CK Mapping",
  "Confidence Level",
  "Human Review Checklist"
];

// ── Helpers ──────────────────────────────────────────────────

// Check whether a Markdown heading (## or #) exists in the text.
function hasSection(text, heading) {
  // Matches # Heading or ## Heading at the start of a line (case-insensitive).
  const pattern = new RegExp("^#{1,3}\\s+" + escapeRegex(heading) + "\\s*$", "im");
  return pattern.test(text);
}

// Extract the text block that follows a given heading, up to the next heading.
// Line-by-line approach avoids multiline-flag $ ambiguity ($ matches end-of-line
// in /m mode, which caused the regex version to always return an empty body).
function getSectionBody(text, heading) {
  const headingRe = new RegExp("^#{1,3}\\s+" + escapeRegex(heading) + "\\s*$", "i");
  const anyHeadingRe = /^#{1,3}\s/;
  const lines = text.split("\n");
  let collecting = false;
  const body = [];
  for (const line of lines) {
    if (!collecting) {
      if (headingRe.test(line)) collecting = true;
    } else {
      if (anyHeadingRe.test(line)) break;
      body.push(line);
    }
  }
  return body.join("\n").trim();
}

// Extract the first KQL code block (```kql ... ```).
function extractKqlBlock(text) {
  const match = text.match(/```(?:kql|kusto)?\s*([\s\S]*?)```/i);
  return match ? match[1].trim() : null;
}

// Detect which known table is referenced in a KQL snippet.
function detectTable(kql) {
  for (const table of KNOWN_TABLES) {
    // Table name must appear at start of a line or after a pipe.
    if (new RegExp("(^|\\|\\s*)" + table + "(\\s|$|\\|)", "m").test(kql)) {
      return table;
    }
  }
  return null;
}

// Escape special regex characters in a plain string.
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ── Core Validator ────────────────────────────────────────────

function validate(text) {
  const results = {
    errors:   [],   // Structural / schema problems → FAIL
    warnings: [],   // Quality gaps → noted but not a hard fail
    passes:   [],   // Checks that passed
    table:    null,
    kqlFound: false
  };

  // 1. Required sections
  for (const section of REQUIRED_SECTIONS) {
    if (hasSection(text, section)) {
      results.passes.push(`Section found: "${section}"`);
    } else {
      results.errors.push(`Missing required section: "${section}"`);
    }
  }

  // 2. KQL code block
  const kql = extractKqlBlock(text);
  if (kql) {
    results.kqlFound = true;
    results.passes.push("KQL code block found");

    // 3. Known table
    const table = detectTable(kql);
    if (table) {
      results.table = table;
      results.passes.push(`Known table detected: ${table}`);
    } else {
      // Check if any table-like word appears at the start of the query
      const firstToken = kql.match(/^\s*(\w+)/);
      const usedName = firstToken ? firstToken[1] : "unknown";
      results.errors.push(
        `Table "${usedName}" is not a known Microsoft Defender XDR table. ` +
        `Known tables for v1: ${KNOWN_TABLES.join(", ")}.`
      );
    }

    // 4. Time filter
    if (/ago\s*\(/.test(kql)) {
      results.passes.push("Time filter (ago()) found");
    } else {
      results.warnings.push("No ago() time filter detected. Unbounded queries may time out or return too many results.");
    }

    // 5. project clause
    if (/\|\s*project\b/.test(kql)) {
      results.passes.push("project clause found");
    } else {
      results.warnings.push("No 'project' clause found. Returning all columns is wasteful and may expose unnecessary data.");
    }

    // 6. Invalid fields for the detected table
    if (results.table && INVALID_FIELDS[results.table]) {
      for (const badField of INVALID_FIELDS[results.table]) {
        if (new RegExp("\\b" + badField + "\\b").test(kql)) {
          results.warnings.push(
            `Invalid field "${badField}" used in ${results.table}. ` +
            `This field does not exist in the table schema.`
          );
        }
      }
    }

  } else {
    results.kqlFound = false;
    results.errors.push("No KQL code block found. Wrap the query in triple backticks: \\`\\`\\`kql ... \\`\\`\\`");
  }

  // 7. False positives section has meaningful content
  const fpBody = getSectionBody(text, "False Positives");
  if (fpBody.length > 20) {
    results.passes.push("False Positives section has content");
  } else if (hasSection(text, "False Positives")) {
    results.warnings.push("False Positives section exists but appears empty or too brief.");
  }

  // 8. What This Query Cannot Prove has content
  const limitBody = getSectionBody(text, "What This Query Cannot Prove");
  if (limitBody.length > 20) {
    results.passes.push('"What This Query Cannot Prove" section has content');
  } else if (hasSection(text, "What This Query Cannot Prove")) {
    results.warnings.push('"What This Query Cannot Prove" section exists but appears empty or too brief.');
  }

  // 9. Human Review Checklist has checkboxes
  const reviewBody = getSectionBody(text, "Human Review Checklist");
  if (/\[[ x]\]/i.test(reviewBody)) {
    results.passes.push("Human Review Checklist contains checklist items");
  } else if (hasSection(text, "Human Review Checklist")) {
    results.warnings.push('Human Review Checklist found but no checkbox items ([ ] or [x]) detected.');
  }

  return results;
}

// ── DOM Rendering ─────────────────────────────────────────────

function renderResults(results) {
  const container = document.getElementById("results");
  const totalErrors = results.errors.length;
  const passed = totalErrors === 0;

  // Show results, hide empty state
  document.getElementById("results-empty").classList.add("hidden");
  container.classList.remove("hidden");

  // Verdict
  const verdictEl = document.getElementById("verdict");
  verdictEl.className = "verdict " + (passed ? "pass" : "fail");
  document.getElementById("verdict-label").textContent = passed ? "PASS" : "FAIL";
  document.getElementById("verdict-summary").textContent = passed
    ? `${results.passes.length} checks passed, ${results.warnings.length} warning(s).`
    : `${totalErrors} error(s) found. ${results.warnings.length} warning(s). ${results.passes.length} check(s) passed.`;

  // Info cards
  document.getElementById("card-table").textContent    = results.table    || "Not detected";
  document.getElementById("card-table").className      = "card-value " + (results.table ? "found" : "missing");
  document.getElementById("card-kql").textContent      = results.kqlFound ? "Found" : "Missing";
  document.getElementById("card-kql").className        = "card-value " + (results.kqlFound ? "found" : "missing");
  document.getElementById("card-errors").textContent   = totalErrors;
  document.getElementById("card-errors").className     = "card-value " + (totalErrors > 0 ? "missing" : "found");
  document.getElementById("card-warnings").textContent = results.warnings.length;
  document.getElementById("card-warnings").className   = "card-value " + (results.warnings.length > 0 ? "" : "found");

  // Build the check list
  const list = document.getElementById("check-list");
  list.innerHTML = "";

  // Errors first
  for (const msg of results.errors) {
    list.appendChild(makeCheckItem("error", "✗", msg));
  }
  // Warnings next
  for (const msg of results.warnings) {
    list.appendChild(makeCheckItem("warn", "⚠", msg));
  }
  // Passes last
  for (const msg of results.passes) {
    list.appendChild(makeCheckItem("pass", "✓", msg));
  }

  // Scroll results into view smoothly
  container.scrollIntoView({ behavior: "smooth", block: "start" });
}

function makeCheckItem(type, icon, text) {
  const item = document.createElement("div");
  item.className = "check-item " + type;

  const iconEl = document.createElement("span");
  iconEl.className = "check-icon";
  iconEl.textContent = icon;

  const textEl = document.createElement("span");
  textEl.className = "check-text";
  textEl.textContent = text;

  item.appendChild(iconEl);
  item.appendChild(textEl);
  return item;
}

// ── Sample Loading ────────────────────────────────────────────

// Fetch a sample file and put it in the textarea.
async function loadSample(filename) {
  try {
    const resp = await fetch("examples/" + filename);
    if (!resp.ok) throw new Error("Could not load sample.");
    const text = await resp.text();
    document.getElementById("detection-input").value = text;
    // Clear any previous results when loading a new sample
    document.getElementById("results").classList.add("hidden");
    document.getElementById("results-empty").classList.remove("hidden");
  } catch (err) {
    alert("Could not load sample file: " + err.message +
      "\n\nMake sure you are running from a local server or the files are co-located.");
  }
}

// ── Event Wiring ──────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("detection-input");

  document.getElementById("btn-validate").addEventListener("click", () => {
    const text = input.value.trim();
    if (!text) {
      alert("Please paste a detection package before validating.");
      return;
    }
    const results = validate(text);
    renderResults(results);
  });

  document.getElementById("btn-good").addEventListener("click", () => {
    loadSample("sample_good_output.md");
  });

  document.getElementById("btn-bad").addEventListener("click", () => {
    loadSample("sample_bad_output.md");
  });

  document.getElementById("btn-clear").addEventListener("click", () => {
    input.value = "";
    document.getElementById("results").classList.add("hidden");
    document.getElementById("results-empty").classList.remove("hidden");
    input.focus();
  });
});
