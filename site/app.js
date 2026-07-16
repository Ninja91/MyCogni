"use strict";

const promiseStories = {
  custody: {
    number: "01",
    label: "LOCAL CUSTODY",
    heading: "Your identity profile is not another SaaS dossier.",
    copy: "Stored source attributes remain encrypted under infrastructure the user controls. Only exact values shown in an authorized plan may leave for a displayed destination; each profile uses an independently random wrapped key.",
    points: ["Encrypted state and evidence", "External wrapping key", "Explicit backup-expiry semantics"]
  },
  proof: {
    number: "02",
    label: "PROOF BEFORE CLAIMS",
    heading: "A request counter never becomes an outcome score.",
    copy: "Submission, acknowledgement, a broker assertion, one absence observation, corroborated verification, and resurfacing are distinct facts. Reports keep the method, timing, limits, and denominator visible.",
    points: ["Method-specific evidence", "Inconclusive stays visible", "Resurfacing creates new history"]
  },
  automation: {
    number: "03",
    label: "HANDS-OFF WHERE EARNED",
    heading: "Automation receives a narrow grant, not blanket trust.",
    copy: "External actions start globally paused. After a separate non-preselected step-up ceremony, a fresh capability can act only inside that exact per-capability authorization. Drift, challenges, stale authority, and unknown outcomes stop the path.",
    points: ["Capability-specific maturity", "Mandatory egress fence", "Global and per-broker pause"]
  },
  clarity: {
    number: "04",
    label: "NO MYSTERY QUEUES",
    heading: "Every unfinished case explains itself.",
    copy: "The interface shows the current state, reason, owner, last evidence, next action, and next date. It never hides a stalled case behind a spinner or converts a missing answer into success.",
    points: ["Visible reason codes", "Named decision owner", "Scheduled next action"]
  }
};

const caseStages = {
  observe: {
    step: "STEP 1 OF 6",
    heading: "A candidate record appears.",
    copy: "After a separate scan-disclosure preview and consent, a read-only connector may query an approved source for a possible public profile. The system records how the match was made without deciding that the record belongs to the user.",
    callout: "name-only candidates can never become automatic confirmed matches.",
    state: "candidate",
    disclosure: "exact approved search values",
    owner: "user or match policy",
    next: "review attribute explanation",
    progress: "16.666%"
  },
  confirm: {
    step: "STEP 2 OF 6",
    heading: "The identity match earns confidence.",
    copy: "The user reviews current and historical attributes and sees why the system thinks this record is theirs. Conflicting or insufficient evidence remains ambiguous.",
    callout: "confirmation is separate from discovery and leaves an auditable explanation.",
    state: "confirmed_present",
    disclosure: "none",
    owner: "authenticated user",
    next: "build minimum request plan",
    progress: "33.333%"
  },
  plan: {
    step: "STEP 3 OF 6",
    heading: "The exact request becomes inspectable.",
    copy: "MyCogni resolves a sourced policy and renders the destination, transport, purpose, attachments, warnings, and minimum identity fields before anything can leave the system.",
    callout: "the immutable plan hash binds the authorized disclosure to the eventual send.",
    state: "planned",
    disclosure: "name + profile URL",
    owner: "deterministic policy core",
    next: "check setup authorization",
    progress: "50%"
  },
  authorize: {
    step: "STEP 4 OF 6",
    heading: "Authority is checked at the action boundary.",
    copy: "The plan must fit an active user grant, confirmed-match policy, connector maturity, destination allowlist, and maximum disclosure schema. Exceptions demand step-up authentication.",
    callout: "authorization is bound to the actor, profile, plan hash, policy version, connector digest, and revocation epoch.",
    state: "approved",
    disclosure: "exact plan frozen",
    owner: "user grant + policy core",
    next: "claim fenced dispatch",
    progress: "66.666%"
  },
  submit: {
    step: "STEP 5 OF 6",
    heading: "The first outbound byte crosses a fence.",
    copy: "A verified connector receives one sealed minimum bundle. The gateway obtains an online first-byte decision and records dispatch start. Typed HTTP and mail are originated exactly; browser TLS retains a disclosed allowed-origin content risk.",
    callout: "a timeout after dispatch becomes outcome_unknown; it is never permission for a blind retry.",
    state: "transport_proven",
    disclosure: "2 authorized fields",
    owner: "intent journal + egress gateway",
    next: "schedule independent verification",
    progress: "83.333%"
  },
  verify: {
    step: "STEP 6 OF 6",
    heading: "Absence is observed, then corroborated.",
    copy: "An independent read-only check runs after the policy delay. One clean observation is labeled exactly that. Only a later corroborating method or time-separated check can satisfy verified removal.",
    callout: "blocks, CAPTCHAs, access denial, personalization uncertainty, and ambiguous searches remain inconclusive.",
    state: "verified_removed",
    disclosure: "approved recheck values",
    owner: "versioned verification policy",
    next: "monitor for resurfacing",
    progress: "100%"
  }
};

const architectureStories = {
  control: {
    label: "AUTHENTICATED USER CONTROL",
    heading: "The user establishes intent and exceptions.",
    copy: "The CLI or local web interface authenticates the actor, records separate scan consent, previews exact disclosures, and requires a dedicated step-up per-capability ceremony before automation can leave global pause.",
    can: "Authorize bounded actions, pause, revoke, export, delete.",
    cannot: "Turn an ambiguous identity match into a safe automatic request."
  },
  core: {
    label: "DETERMINISTIC TRUSTED CORE",
    heading: "Policy and state transitions stay explainable.",
    copy: "The modular core owns identity, authority, policy, disclosure plans, cases, jobs, evidence semantics, and the external-intent journal. It does not import untrusted connector code.",
    can: "Decide policy, freeze plans, revalidate fences, record outcomes.",
    cannot: "Delegate authorization or verification truth to a connector or model."
  },
  vault: {
    label: "ENCRYPTED STATE + KEY CATALOG",
    heading: "Data and the ability to recover it are separated.",
    copy: "Profile data and evidence are field or object encrypted. Independent random profile keys are wrapped by an OS keychain or cloud KMS key and tracked through deletion and backup expiry.",
    can: "Encrypt bounded records, export profiles, enforce deletion semantics.",
    cannot: "Recreate a deleted profile key from an installation root."
  },
  runner: {
    label: "ISOLATED CONNECTOR ARTIFACT",
    heading: "Each extension gets one sealed task.",
    copy: "A digest-pinned OCI or constrained WASI artifact receives a minimal, one-time action envelope. It runs rootless with read-only filesystems, resource limits, and no core mounts.",
    can: "Perform one declared capability and return structured evidence.",
    cannot: "Access the database, vault, Docker socket, host network, or reusable credentials."
  },
  egress: {
    label: "MANDATORY EGRESS POLICY GATEWAY",
    heading: "Every outbound byte meets the current decision.",
    copy: "The gateway checks the intent fence, connector digest, origin, public IP resolution, protocol, disclosure schema, and byte budget immediately before transmission.",
    can: "Permit an exact connection and capture bounded transport evidence.",
    cannot: "Grant arbitrary internet access or override a pause, revocation, or stale lease."
  },
  broker: {
    label: "EXTERNAL HOSTILE BOUNDARY",
    heading: "A valid destination is still not trusted code.",
    copy: "Broker sites, portals, inboxes, redirects, scripts, and responses are treated as hostile content. Procedures and terms can drift at any time.",
    can: "Receive the exact authorized disclosure and return a bounded response.",
    cannot: "Declare MyCogni's independent verification state."
  },
  assist: {
    label: "OPTIONAL POST-V1 LOCAL INTELLIGENCE",
    heading: "A model may suggest. It never commands.",
    copy: "The default adapter is null. A future opt-in runtime may receive deterministically sanitized bounded tasks and return schema-validated suggestions with supporting spans.",
    can: "Reduce review time in a measured advisory task if it passes shadow evaluation.",
    cannot: "Use tools, network, vault, database, raw PII, or mutate policy, state, disclosure, verification, or execution."
  }
};

const safetyStories = {
  ambiguous: {
    badge: "AUTOMATION STOPS",
    heading: "The match stays ambiguous.",
    copy: "MyCogni presents the attribute-level explanation and asks the user to confirm or reject it. A name-only or conflicting match cannot enter automatic submission.",
    state: "ambiguous_match",
    recovery: "user review or stronger evidence"
  },
  challenge: {
    badge: "USER TASK CREATED",
    heading: "The human-visible challenge stays human.",
    copy: "CAPTCHA, MFA, identity documents, account login, and changed terms suspend automation. MyCogni records the blocker and provides a guided next step without bypassing the control.",
    state: "needs_user_action",
    recovery: "user completes official flow"
  },
  timeout: {
    badge: "RETRY BLOCKED",
    heading: "Unknown means unknown—not unsent.",
    copy: "If the process times out after dispatch begins, the journal records outcome_unknown. The system reconciles through a receipt, inbox, portal, or non-mutating status check before considering another send.",
    state: "outcome_unknown",
    recovery: "manual or automated reconciliation"
  },
  drift: {
    badge: "CONNECTOR QUARANTINED",
    heading: "Fresh trust expires on purpose.",
    copy: "A destination, disclosure, terms, DOM, policy, or behavior change demotes the affected capability. Automatic submission stays unavailable until synthetic tests and qualified review re-establish trust.",
    state: "quarantined",
    recovery: "revalidate, review, and repromote"
  },
  ai: {
    badge: "SUGGESTION ONLY",
    heading: "The deterministic core keeps authority.",
    copy: "A local model response is untrusted data. Schema validation, supporting spans, and a visible review surface can make it useful, but it cannot authorize, disclose, submit, or verify anything.",
    state: "untrusted_suggestion",
    recovery: "human review or deterministic fallback"
  }
};

const phases = {
  foundation: {
    label: "WEEKS 0–4",
    heading: "Build the foundation that can say “no.”",
    copy: "Land locked project boundaries, a deterministic simulator, hermetic network-deny CI, stable threat IDs, and executable auth, key, backup, egress, runner, and browser spikes.",
    gates: ["P0 spikes dispositioned", "Synthetic-only test path", "Threat-to-test traceability"]
  },
  kernel: {
    label: "WEEKS 4–9",
    heading: "Make the local kernel durable before it sees the web.",
    copy: "Implement authentication, encrypted identity, jobs and evidence, online backup/restore, and the generic journal, pause epoch, restore epoch, and fail-closed gateway required even for live scans.",
    gates: ["Auth/key/restore tests pass", "Outbound action base fails closed", "Separate discovery consent exists"]
  },
  preview: {
    label: "WEEKS 9–14",
    heading: "Make exposure visible before asking for trust.",
    copy: "Run separately authorized read-only searches, explain candidates, expose evidence and case state, and learn from a preregistered preview cohort without sending a removal request.",
    gates: ["Exact scan disclosure", "Preview precision denominators", "Zero removal submissions"]
  },
  guided: {
    label: "WEEKS 14–19",
    heading: "Turn exact plans into understandable guided work.",
    copy: "Add immutable request plans, disclosure ledgers, manual and email-draft flows, policy provenance, export, deletion, and restore.",
    gates: ["Proof comprehension passes", "Every field disclosure understood", "Restore and deletion reports are honest"]
  },
  automation: {
    label: "WEEKS 19–26",
    heading: "Automate only the narrow path that earned it.",
    copy: "Ship signed update and artifact verification, restore-safe journaling, transport-specific gateways, and 2–5 trusted automatic capabilities only after shared and capability human reviews.",
    gates: ["Shared + capability reviews", "Per-capability authority/match gate", "Kill switches and reconciliation pass"]
  },
  v1: {
    label: "WEEKS 26–32",
    heading: "Harden a small local product into a release candidate.",
    copy: "Add corroborated verification, resurfacing, signed multi-architecture images, SBOM and provenance, restore drills, accessibility, and usability gates.",
    gates: ["Zero P0; no enabled P1", "Signed release-candidate artifacts", "Restore and resilience drills"]
  },
  stable: {
    label: "WEEKS 32–40+",
    heading: "Earn—or fail—the stable automatic-remover claim.",
    copy: "Maintain separate preview, guided, and automatic cohorts. Automatic behavior must accumulate at least twelve weeks and a mature day-90 denominator before stable eligibility.",
    gates: ["Automatic cohort ≥12 weeks", "Day-90 denominator mature", "Every safety + viability gate passes"]
  }
};

function setText(id, value) {
  const node = document.getElementById(id);
  if (node) node.textContent = value;
}

function setList(id, items) {
  const list = document.getElementById(id);
  if (!list) return;
  list.replaceChildren(...items.map((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    return li;
  }));
}

function activateTabs(selector, dataAttribute, render) {
  const tabs = [...document.querySelectorAll(selector)];
  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => {
      tabs.forEach((candidate) => {
        candidate.setAttribute("aria-selected", String(candidate === tab));
        candidate.tabIndex = candidate === tab ? 0 : -1;
      });
      render(tab.dataset[dataAttribute], tab);
    });
    tab.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      let next = index;
      if (["ArrowRight", "ArrowDown"].includes(event.key)) next = (index + 1) % tabs.length;
      if (["ArrowLeft", "ArrowUp"].includes(event.key)) next = (index - 1 + tabs.length) % tabs.length;
      if (event.key === "Home") next = 0;
      if (event.key === "End") next = tabs.length - 1;
      tabs[next].click();
      tabs[next].focus();
    });
  });
}

activateTabs("[data-promise]", "promise", (key, tab) => {
  const story = promiseStories[key];
  setText("promise-number", story.number);
  setText("promise-label", story.label);
  setText("promise-heading", story.heading);
  setText("promise-copy", story.copy);
  setList("promise-points", story.points);
  const panel = document.getElementById("promise-panel");
  if (panel) panel.setAttribute("aria-labelledby", tab.id);
});

activateTabs("[data-case]", "case", (key, tab) => {
  const stage = caseStages[key];
  setText("case-step-label", stage.step);
  setText("case-heading", stage.heading);
  setText("case-copy", stage.copy);
  setText("case-callout", `Control: ${stage.callout}`);
  setText("case-state", stage.state);
  setText("case-disclosure", stage.disclosure);
  setText("case-owner", stage.owner);
  setText("case-next", stage.next);
  const progress = document.getElementById("case-progress-bar");
  if (progress) progress.style.width = stage.progress;
  const panel = document.getElementById("case-panel");
  if (panel) panel.setAttribute("aria-labelledby", tab.id);
});

activateTabs("[data-phase]", "phase", (key, tab) => {
  const phase = phases[key];
  setText("phase-label", phase.label);
  setText("phase-heading", phase.heading);
  setText("phase-copy", phase.copy);
  setList("phase-gates", phase.gates);
  const panel = document.getElementById("phase-panel");
  if (panel) panel.setAttribute("aria-labelledby", tab.id);
});

document.querySelectorAll("[data-arch]").forEach((button) => {
  button.addEventListener("click", () => {
    const story = architectureStories[button.dataset.arch];
    document.querySelectorAll("[data-arch]").forEach((candidate) => {
      const selected = candidate === button;
      candidate.classList.toggle("is-selected", selected);
      candidate.setAttribute("aria-pressed", String(selected));
    });
    setText("arch-label", story.label);
    setText("arch-heading", story.heading);
    setText("arch-copy", story.copy);
    setText("arch-can", story.can);
    setText("arch-cannot", story.cannot);
  });
});

document.querySelectorAll("[data-scenario]").forEach((button) => {
  button.addEventListener("click", () => {
    const story = safetyStories[button.dataset.scenario];
    document.querySelectorAll("[data-scenario]").forEach((candidate) => {
      const selected = candidate === button;
      candidate.classList.toggle("is-selected", selected);
      candidate.setAttribute("aria-pressed", String(selected));
    });
    setText("scenario-badge", story.badge);
    setText("scenario-heading", story.heading);
    setText("scenario-copy", story.copy);
    setText("scenario-state", story.state);
    setText("scenario-recovery", story.recovery);
  });
});

const progressBar = document.getElementById("reading-progress-bar");
function updateProgress() {
  const scrollable = document.documentElement.scrollHeight - window.innerHeight;
  const progress = scrollable > 0 ? Math.min(1, window.scrollY / scrollable) : 0;
  if (progressBar) progressBar.style.width = `${progress * 100}%`;
}
window.addEventListener("scroll", updateProgress, { passive: true });
updateProgress();

const chapterSections = [...document.querySelectorAll("[data-chapter]")];
if ("IntersectionObserver" in window) {
  const observer = new IntersectionObserver((entries) => {
    const visible = entries
      .filter((entry) => entry.isIntersecting)
      .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
    if (!visible) return;
    document.querySelectorAll("[data-nav]").forEach((link) => {
      link.classList.toggle("is-active", link.dataset.nav === visible.target.dataset.chapter);
    });
  }, { rootMargin: "-25% 0px -55%", threshold: [0.05, 0.2, 0.5] });
  chapterSections.forEach((section) => observer.observe(section));
}

document.querySelectorAll(".review-list details").forEach((detail) => {
  detail.addEventListener("toggle", () => {
    if (!detail.open) return;
    document.querySelectorAll(".review-list details").forEach((other) => {
      if (other !== detail) other.open = false;
    });
  });
});
