import { createHash } from "node:crypto";
import dns from "node:dns/promises";
import { readdir, readFile, readlink, rm, stat, statfs } from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import { chromium } from "playwright";

const FIXTURE = "/opt/mycogni-browser/synthetic.html";
const EXPECTED_SHA256 = "c7e66496ebde57629d55d931d61c1f8675bb1e7148dafc4e042d547c0c38b178";
const TMP = "/tmp/mycogni-browser";
const FORBIDDEN_SANDBOX_FLAGS = [
  "--no-sandbox",
  "--disable-setuid-sandbox",
  "--disable-seccomp-filter-sandbox",
  "--disable-namespace-sandbox",
  "--disable-gpu-sandbox",
  "--single-process",
  "--in-process-gpu",
  "--no-zygote",
  "--no-zygote-sandbox",
];

const watchdog = setTimeout(() => {
  process.stderr.write("SPIKE-BROWSER exceeded its fixed 20-second decision deadline\n");
  process.exit(124);
}, 20_000);

function denySocket(host, port) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`socket attempt timed out: ${host}`));
    }, 1500);
    socket.once("connect", () => {
      clearTimeout(timer);
      socket.destroy();
      reject(new Error(`unexpected socket connection: ${host}`));
    });
    socket.once("error", error => {
      clearTimeout(timer);
      resolve({ host, denied: true, code: error.code ?? "UNKNOWN" });
    });
  });
}

async function denyDns(name) {
  try {
    await dns.lookup(name);
    throw new Error(`unexpected DNS result: ${name}`);
  } catch (error) {
    if (error.message === `unexpected DNS result: ${name}`) throw error;
    return { name, denied: true, code: error.code ?? "UNKNOWN" };
  }
}

async function chromiumProcesses() {
  const processes = [];
  for (const entry of await readdir("/proc", { withFileTypes: true })) {
    if (!entry.isDirectory() || !/^\d+$/.test(entry.name)) continue;
    try {
      const command = (await readFile(`/proc/${entry.name}/cmdline`, "utf8"))
        .split("\0").filter(Boolean);
      if (!command.some(value => value.includes("/ms-playwright/chromium"))) continue;
      const status = Object.fromEntries((await readFile(`/proc/${entry.name}/status`, "utf8"))
        .split("\n").filter(line => line.includes(":"))
        .map(line => {
          const [key, ...parts] = line.split(":");
          return [key, parts.join(":").trim()];
        }));
      const namespaces = Object.fromEntries(await Promise.all(
        ["user", "mnt", "pid", "net"].map(async name =>
          [name, await readlink(`/proc/${entry.name}/ns/${name}`)])));
      let root;
      try {
        root = await readlink(`/proc/${entry.name}/root`);
      } catch (error) {
        if (error.code !== "EACCES") throw error;
        root = "inaccessible:EACCES";
      }
      let rootStat;
      try {
        const value = await stat(`/proc/${entry.name}/root`);
        rootStat = { dev: Number(value.dev), ino: Number(value.ino), disposition: "visible" };
      } catch (error) {
        if (error.code === "ESRCH" || error.code === "ENOENT") continue;
        if (error.code !== "EACCES") throw error;
        rootStat = { dev: null, ino: null, disposition: "access-denied" };
      }
      let outerSentinel;
      try {
        await stat(`/proc/${entry.name}/root/opt/mycogni-browser/synthetic.html`);
        outerSentinel = "visible";
      } catch (error) {
        if (error.code === "ESRCH" || error.code === "ENOENT") outerSentinel = "absent";
        else if (error.code === "EACCES") outerSentinel = "access-denied";
        else throw error;
      }
      processes.push({
        pid: Number(entry.name), command, status, namespaces, root, rootStat, outerSentinel,
      });
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
  return processes;
}

const fixtureBytes = await readFile(FIXTURE);
const fixtureSha256 = createHash("sha256").update(fixtureBytes).digest("hex");
if (fixtureSha256 !== EXPECTED_SHA256) throw new Error("synthetic fixture digest mismatch");
const selfStatus = Object.fromEntries((await readFile("/proc/self/status", "utf8"))
  .split("\n").filter(line => line.includes(":"))
  .map(line => {
    const [key, ...parts] = line.split(":");
    return [key, parts.join(":").trim()];
  }));
for (const field of ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]) {
  if (!/^0+$/.test(selfStatus[field])) throw new Error(`outer capability set is nonzero: ${field}`);
}
if (selfStatus.NoNewPrivs !== "1" || selfStatus.Seccomp !== "2") {
  throw new Error("outer process lacks no-new-privileges or seccomp filtering");
}
const cgroup = {
  cpuMax: (await readFile("/sys/fs/cgroup/cpu.max", "utf8")).trim(),
  memoryMax: (await readFile("/sys/fs/cgroup/memory.max", "utf8")).trim(),
  pidsMax: (await readFile("/sys/fs/cgroup/pids.max", "utf8")).trim(),
};
if (cgroup.cpuMax !== "100000 100000" || cgroup.memoryMax !== "1073741824" ||
    cgroup.pidsMax !== "128") throw new Error("effective cgroup-v2 limits mismatch");
const sharedMemory = await statfs("/dev/shm");
if (Number(sharedMemory.blocks) * Number(sharedMemory.bsize) !== 268435456) {
  throw new Error("private shared-memory size mismatch");
}

const server = http.createServer((request, response) => {
  if (request.method !== "GET" || request.url !== "/synthetic.html") {
    response.writeHead(404, { "content-type": "text/plain", "cache-control": "no-store" });
    response.end("not found");
    return;
  }
  response.writeHead(200, {
    "content-type": "text/html; charset=utf-8",
    "content-length": fixtureBytes.length,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  response.end(fixtureBytes);
});
await new Promise((resolve, reject) => {
  server.once("error", reject);
  server.listen({ host: "127.0.0.1", port: 0, exclusive: true }, resolve);
});
const address = server.address();
if (!address || typeof address === "string" || address.address !== "127.0.0.1") {
  throw new Error("synthetic fixture did not bind exact loopback");
}
const fixtureUrl = `http://127.0.0.1:${address.port}/synthetic.html`;

const browser = await chromium.launch({
  headless: true,
  chromiumSandbox: true,
  ignoreDefaultArgs: ["--disable-dev-shm-usage"],
  tracesDir: undefined,
});

let processEvidence;
let sandboxEvidence;
try {
  const context = await browser.newContext({
    acceptDownloads: false,
    bypassCSP: false,
    javaScriptEnabled: true,
    permissions: [],
    serviceWorkers: "block",
  });
  const deniedBrowserRequests = [];
  await context.route("**/*", route => {
    if (route.request().url() === fixtureUrl && route.request().method() === "GET") {
      return route.continue();
    }
    deniedBrowserRequests.push(route.request().url());
    return route.abort("blockedbyclient");
  });
  const page = await context.newPage();
  const requests = [];
  page.on("request", request => requests.push(request.url()));
  await page.goto(fixtureUrl, { waitUntil: "load" });
  const observed = await page.locator("main").evaluate(element => ({
    origin: element.getAttribute("data-fixture-origin"),
    heading: element.querySelector("h1")?.textContent,
    text: element.querySelector("p")?.textContent,
    activeElements: element.querySelectorAll("a,form,input,button,script,img,iframe,object,embed").length,
  }));
  if (JSON.stringify(observed) !== JSON.stringify({
    origin: "fixture.browser.mycogni.test",
    heading: "Synthetic browser boundary probe",
    text: "No person, broker, credential, request, submission, or removal outcome exists here.",
    activeElements: 0,
  })) throw new Error("synthetic fixture content mismatch");
  if (requests.length !== 1 || requests[0] !== fixtureUrl) {
    throw new Error("browser observed an undeclared request");
  }
  const browserDenials = await page.evaluate(async () => {
    const fetchDenied = await fetch("http://127.0.0.1:9/fetch").then(
      () => false, () => true);
    const imageDenied = await new Promise(resolve => {
      const image = new Image();
      image.onload = () => resolve(false);
      image.onerror = () => resolve(true);
      image.src = "http://127.0.0.1:9/image.png";
    });
    const workerDenied = await new Promise(resolve => {
      try {
        const worker = new Worker("http://127.0.0.1:9/worker.js");
        worker.onmessage = () => { worker.terminate(); resolve(false); };
        worker.onerror = () => { worker.terminate(); resolve(true); };
      } catch { resolve(true); }
    });
    const websocketDenied = await new Promise(resolve => {
      const socket = new WebSocket("ws://127.0.0.1:9/socket");
      socket.onopen = () => { socket.close(); resolve(false); };
      socket.onerror = () => resolve(true);
    });
    return { fetchDenied, imageDenied, workerDenied, websocketDenied };
  });
  if (!Object.values(browserDenials).every(Boolean)) {
    throw new Error("browser alternate request denial failed");
  }
  const navigationPage = await context.newPage();
  const navigationDenied = await navigationPage.goto("http://127.0.0.1:9/navigation").then(
    () => false, () => true);
  await navigationPage.close();
  if (!navigationDenied || deniedBrowserRequests.length !== 1 ||
      deniedBrowserRequests[0] !== "http://127.0.0.1:9/navigation") {
    throw new Error("browser navigation/request route denial failed");
  }
  const cdp = await browser.newBrowserCDPSession();
  const cdpProcessInfo = await cdp.send("SystemInfo.getProcessInfo");
  await cdp.detach();
  const rendererPids = new Set(cdpProcessInfo.processInfo
    .filter(process => process.type === "renderer")
    .map(process => process.id));
  if (rendererPids.size === 0) throw new Error("CDP reported no renderer process");
  processEvidence = await chromiumProcesses();
  if (!processEvidence.length) throw new Error("Chromium process evidence unavailable");
  const browserProcess = processEvidence.find(process =>
    !process.command.some(argument => argument.startsWith("--type=")));
  if (!browserProcess || browserProcess.command.some(argument =>
    FORBIDDEN_SANDBOX_FLAGS.includes(argument))) {
    throw new Error("Chromium sandbox was disabled");
  }
  if (processEvidence.some(process => process.command.includes("--disable-dev-shm-usage"))) {
    throw new Error("Chromium bypassed the bounded private shared-memory mount");
  }
  const renderer = processEvidence.find(process => rendererPids.has(process.pid));
  if (!renderer) throw new Error("Chromium renderer process evidence unavailable");
  if (processEvidence.some(process => process.status.Seccomp !== "2")) {
    throw new Error("Chromium process escaped seccomp filtering");
  }
  const ZERO_CAP = "0000000000000000";
  const NESTED_BOUNDING_CAP = "000001ffffffffff";
  const NESTED_SYS_ADMIN_CAP = "0000000000200000";
  const capabilityFields = ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"];
  const exactCapabilities = (process, expected) => capabilityFields.every(
    field => process.status[field] === expected[field]);
  const allZero = process => capabilityFields.every(field => process.status[field] === ZERO_CAP);
  const sameOuterBoundary = process => ["user", "mnt", "pid", "net"].every(
    name => process.namespaces[name] === browserProcess.namespaces[name]) &&
    process.rootStat.disposition === "visible" &&
    process.rootStat.dev === browserProcess.rootStat.dev &&
    process.rootStat.ino === browserProcess.rootStat.ino;
  const nestedBoundary = process =>
    process.namespaces.user !== browserProcess.namespaces.user &&
    process.namespaces.pid !== browserProcess.namespaces.pid &&
    process.namespaces.net !== browserProcess.namespaces.net &&
    process.namespaces.mnt === browserProcess.namespaces.mnt &&
    process.rootStat.disposition === "visible" &&
    (process.rootStat.dev !== browserProcess.rootStat.dev ||
      process.rootStat.ino !== browserProcess.rootStat.ino) &&
    process.outerSentinel !== "visible";
  const zeroNested = {
    CapInh: ZERO_CAP, CapPrm: ZERO_CAP, CapEff: ZERO_CAP,
    CapBnd: NESTED_BOUNDING_CAP, CapAmb: ZERO_CAP,
  };
  const sysAdminNested = {
    CapInh: ZERO_CAP, CapPrm: NESTED_SYS_ADMIN_CAP, CapEff: NESTED_SYS_ADMIN_CAP,
    CapBnd: NESTED_BOUNDING_CAP, CapAmb: ZERO_CAP,
  };
  if (!allZero(browserProcess)) {
    throw new Error("outer Chromium browser capability set is nonzero");
  }
  const roleCounts = { outerZygote: 0, nestedZygoteZero: 0, nestedZygoteSysAdmin: 0,
    gpu: 0, utility: 0, renderer: 0 };
  for (const process of processEvidence) {
    if (process === browserProcess) continue;
    const command = process.command.join(" ");
    const role = command.match(/(?:^|\s)--type=([^\s]+)/)?.[1];
    if (role === "zygote" && command.includes("--no-zygote-sandbox")) {
      if (!sameOuterBoundary(process) || !allZero(process)) {
        throw new Error("outer no-zygote-sandbox process escaped exact zero-capability policy");
      }
      roleCounts.outerZygote += 1;
    } else if (role === "zygote") {
      if (!nestedBoundary(process)) throw new Error("nested zygote boundary mismatch");
      if (exactCapabilities(process, zeroNested)) roleCounts.nestedZygoteZero += 1;
      else if (exactCapabilities(process, sysAdminNested)) roleCounts.nestedZygoteSysAdmin += 1;
      else throw new Error("nested zygote capability set escaped exact allowlist");
    } else if (role === "gpu-process" || role === "utility") {
      if (!sameOuterBoundary(process) || !allZero(process)) {
        throw new Error(`outer Chromium ${role} process escaped exact zero-capability policy`);
      }
      roleCounts[role === "gpu-process" ? "gpu" : "utility"] += 1;
    } else if (role === "renderer") {
      if (!nestedBoundary(process) || !exactCapabilities(process, zeroNested)) {
        throw new Error("nested renderer escaped exact capability/boundary policy");
      }
      roleCounts.renderer += 1;
    } else {
      throw new Error(`unknown Chromium process role: ${role ?? "browser-duplicate"}`);
    }
  }
  if (JSON.stringify(roleCounts) !== JSON.stringify({
    outerZygote: 1, nestedZygoteZero: 1, nestedZygoteSysAdmin: 1,
    gpu: 1, utility: 1, renderer: 1,
  })) throw new Error(`Chromium process role counts mismatch: ${JSON.stringify(roleCounts)}`);
  if (processEvidence.some(process => process.status.NoNewPrivs !== "1")) {
    throw new Error("Chromium process escaped no-new-privileges");
  }
  if (processEvidence.some(process => !process.status.Uid?.split(/\s+/).every(uid => uid === "65532"))) {
    throw new Error("Chromium process did not retain the dedicated UID");
  }
  const nodeNamespaces = Object.fromEntries(await Promise.all(
    ["user", "mnt", "pid", "net"].map(async name => [name, await readlink(`/proc/self/ns/${name}`)])));
  if (renderer.namespaces.user === nodeNamespaces.user ||
      renderer.namespaces.pid === nodeNamespaces.pid ||
      renderer.namespaces.net === nodeNamespaces.net) {
    throw new Error(`Chromium renderer namespace proof failed: ${JSON.stringify({
      userNested: renderer.namespaces.user !== nodeNamespaces.user,
      mountNested: renderer.namespaces.mnt !== nodeNamespaces.mnt,
      pidNested: renderer.namespaces.pid !== nodeNamespaces.pid,
      networkShared: renderer.namespaces.net === nodeNamespaces.net,
      browserFilters: browserProcess.status.Seccomp_filters,
      rendererFilters: renderer.status.Seccomp_filters,
    })}`);
  }
  const browserSeccompFilters = Number(browserProcess.status.Seccomp_filters);
  const rendererSeccompFilters = Number(renderer.status.Seccomp_filters);
  if (!Number.isInteger(browserSeccompFilters) || !Number.isInteger(rendererSeccompFilters) ||
      rendererSeccompFilters <= browserSeccompFilters) {
    throw new Error("Chromium renderer did not add its internal seccomp filter");
  }
  if (renderer.root === browserProcess.root && renderer.root !== "inaccessible:EACCES") {
    throw new Error("Chromium renderer root was not distinct or access-denied");
  }
  const nodeRootStat = await stat("/proc/self/root");
  if (Number(nodeRootStat.dev) !== browserProcess.rootStat.dev ||
      Number(nodeRootStat.ino) !== browserProcess.rootStat.ino) {
    throw new Error("Chromium browser process unexpectedly changed filesystem root");
  }
  if (browserProcess.outerSentinel !== "visible") {
    throw new Error("Chromium browser process cannot see the declared image sentinel");
  }
  let rendererRootDisposition;
  if (renderer.rootStat.disposition === "visible") {
    if (renderer.rootStat.dev === browserProcess.rootStat.dev &&
        renderer.rootStat.ino === browserProcess.rootStat.ino) {
      throw new Error("Chromium renderer root matches the outer image root");
    }
    rendererRootDisposition = "distinct-dev-inode";
  } else {
    rendererRootDisposition = "access-denied";
  }
  if (renderer.outerSentinel === "visible") {
    throw new Error("Chromium renderer root exposes the outer image sentinel");
  }
  sandboxEvidence = {
    browserSeccompFilters,
    rendererSeccompFilters,
    rendererUserNamespaceNested: renderer.namespaces.user !== nodeNamespaces.user,
    rendererPidNamespaceNested: renderer.namespaces.pid !== nodeNamespaces.pid,
    rendererNetworkNamespaceNested: renderer.namespaces.net !== nodeNamespaces.net,
    rendererMountNamespaceShared: renderer.namespaces.mnt === nodeNamespaces.mnt,
    rendererRootDistinctOrInaccessible: true,
    rendererRootDisposition,
    rendererBoundingCapabilities: renderer.status.CapBnd,
    nestedZygoteBoundingCapabilities: NESTED_BOUNDING_CAP,
    nestedZygoteSysAdminCapabilities: NESTED_SYS_ADMIN_CAP,
    nestedMountNamespaceShared: true,
  };
  await new Promise(resolve => setTimeout(resolve, 1000));
  await context.close();
} finally {
  await browser.close();
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}

const socketDenials = await Promise.all([
  denySocket("127.0.0.1", 9),
  denySocket("::1", 9),
  denySocket("198.51.100.1", 443),
  denySocket("203.0.113.1", 443),
  denySocket("2001:db8::1", 443),
  denySocket("1.1.1.1", 443),
  denySocket("169.254.169.254", 80),
  denySocket("192.168.65.2", 80),
]);
const dnsDenials = await Promise.all([
  denyDns("fixture.browser.mycogni.test"),
  denyDns("metadata.invalid"),
]);
const tmpEntries = await readdir(TMP);
if (tmpEntries.some(entry => entry !== ".cache")) {
  throw new Error(`undeclared browser temporary artifacts survived shutdown: ${tmpEntries.sort().join(",")}`);
}
await rm(`${TMP}/.cache`, { recursive: true, force: true });
if ((await readdir(TMP)).length !== 0) throw new Error("browser temporary cleanup failed");
clearTimeout(watchdog);

process.stdout.write(`${JSON.stringify({
  schema: "mycogni.browser-spike.v1",
  fixture: "fixture.browser.mycogni.test",
  fixtureSha256,
  chromiumSandboxRequested: true,
  chromiumProcesses: processEvidence.length,
  rendererObserved: true,
  sandbox: sandboxEvidence,
  cgroup,
  outerCapabilitiesZero: true,
  chromiumCapabilityRolesExact: true,
  outerChromiumCapabilitiesZero: true,
  browserBoundingCapabilitiesZero: true,
  namespaceScopedZygoteSysAdminObserved: true,
  noSandboxFlagAbsent: true,
  privateShmUsed: true,
  seccompFiltered: true,
  chromiumInternalSeccompFilterAdded: true,
  noNewPrivileges: true,
  uid: 65532,
  allowedLoopbackRequests: 1,
  browserAlternateRequestsDenied: true,
  socketDenials,
  dnsDenials,
  temporaryArtifacts: 0,
})}\n`);
