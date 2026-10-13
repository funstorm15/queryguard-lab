"use strict";

const $ = (id) => document.getElementById(id);
const titles = {
  "baseline-orders": "Мои заказы", "baseline-total": "Сумма продаж",
  "baseline-customer": "Апостроф в имени клиента", "tenant-override": "Обход прав пользователя",
  "private-column": "Чтение скрытого поля", "secret-table": "Доступ к таблице секретов",
  "delete-orders": "Попытка удалить заказы", "customer-sqli": "SQL-инъекция в имени",
  "indirect-context": "Инструкция внутри документа",
};
const labels = {
  vulnerability: "Нарушение", blocked: "Заблокировано", passed: "Пройдено",
  not_observed: "Не обнаружено", error: "Ошибка", failed: "Регрессия", inconclusive: "Неоднозначно",
};
let config = null;
let busy = false;
let lastRun = null;
let suite = null;

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function badge(outcome) {
  return node("span", `badge ${Object.hasOwn(labels, outcome) ? outcome : ""}`, labels[outcome] || outcome);
}

function error(message = "") {
  $("error").hidden = !message;
  $("error").textContent = message;
}

function setBusy(value) {
  busy = value;
  for (const element of document.querySelectorAll("#prompt-form button, #prompt-form input, #prompt-form textarea, .settings select, .settings input, #scan-button, .scenario")) {
    element.disabled = value;
  }
  $("download-run").disabled = value || !lastRun;
  $("download-suite").disabled = value || !suite?.findings.length;
}

function settings() {
  if ($("provider").value === "ollama" && !$("model").value.trim()) {
    throw new Error("Укажи точное имя установленной модели из ollama list.");
  }
  return { provider: $("provider").value, model: $("model").value.trim(), tenant: $("tenant").value };
}

async function request(payload) {
  const response = await fetch("/api/run", {
    method: "POST", headers: { "Content-Type": "application/json", "X-QueryGuard-Token": config.token },
    body: JSON.stringify(payload),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Ошибка сервера: ${response.status}`);
  return data;
}

function showView(view) {
  $("playground-view").hidden = view !== "playground";
  $("suite-view").hidden = view !== "suite";
  $("breadcrumb").textContent = view === "suite" ? "Проверки" : "Песочница";
  for (const button of document.querySelectorAll("[data-view]")) {
    const selected = button.dataset.view === view;
    button.classList.toggle("active", selected);
    if (selected) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  }
}

function updateCount() { $("char-count").textContent = `${$("prompt").value.length} / 8192`; }

function resultsInto(container, results) {
  container.replaceChildren();
  for (const result of results) {
    const card = node("article", "result-card");
    const head = node("div", "result-head");
    head.append(node("h3", "", result.mode === "vulnerable" ? "Уязвимый режим" : "Защищённый режим"), badge(result.outcome));
    const body = node("div", "result-content");
    const meta = node("div", "result-meta");
    meta.append(node("span", "", result.simulated ? "DEMO / симулятор" : result.provider), node("span", "", `tenant: ${result.tenant}`), node("span", "", `${result.rows.length} строк`));
    body.append(meta, node("h4", "", "SQL · запрос к базе"), node("pre", "", result.sql || "SQL не выполнялся: запрос остановлен до обращения к базе."));
    if (result.parameters.length) body.append(node("h4", "", "Параметры · переданы отдельно от SQL"), node("pre", "", JSON.stringify(result.parameters)));
    body.append(node("h4", "", "Ответ базы"));
    if (result.rows.length) {
      const wrap = node("div", "data-wrap");
      const table = node("table", "data-table");
      const columns = [...new Set(result.rows.flatMap((row) => Object.keys(row)))];
      const thead = node("thead");
      const tr = node("tr");
      columns.forEach((column) => tr.append(node("th", "", column)));
      thead.append(tr);
      const tbody = node("tbody");
      for (const row of result.rows) {
        const dataRow = node("tr");
        for (const column of columns) {
          const cell = node("td", "", row[column] === null ? "NULL" : row[column] ?? "—");
          cell.title = cell.textContent;
          dataRow.append(cell);
        }
        tbody.append(dataRow);
      }
      table.append(thead, tbody);
      wrap.append(table);
      body.append(wrap);
    } else {
      body.append(node("p", "result-info", result.execution === "blocked" ? "План отклонён. Данные не запрашивались." : "Строки не возвращены."));
    }
    if (result.truncated) body.append(node("p", "error-copy", "Показаны только первые 100 строк."));
    if (result.error) body.append(node("p", "error-copy", result.error));
    body.append(node("h4", "", "Наблюдаемый результат"));
    if (result.evidence.length) {
      const list = node("ul", "evidence");
      result.evidence.forEach((line) => list.append(node("li", "", line)));
      body.append(list);
    } else {
      const explanations = {
        blocked: "Валидатор не разрешил выполнить этот план.",
        passed: "Получен ожидаемый результат тестового сценария.",
        failed: "Обычный запрос не дал ожидаемый результат. Это регрессия, а не успешная защита.",
        error: "Проверка не завершилась. Ошибка не считается доказательством защиты.",
        inconclusive: "Результат отличается от ожидаемого, но утечка не подтверждена.",
      };
      body.append(node("p", "result-info", explanations[result.outcome] || "Нарушение не обнаружено в рамках этой проверки. Это не гарантия безопасности."));
    }
    if (result.remediation) body.append(node("h4", "", "Рекомендуемый контроль"), node("p", "result-info", result.remediation));
    const raw = node("details", "raw-output");
    raw.append(node("summary", "", "Исходный ответ и входные данные"), node("h4", "", "Ответ модели / симулятора"), node("pre", "", result.model_output), node("h4", "", "Запрос пользователя"), node("pre", "", result.prompt));
    if (result.retrieved_context) raw.append(node("h4", "", "Недоверенный контекст"), node("pre", "", result.retrieved_context));
    body.append(raw);
    card.append(head, body);
    container.append(card);
  }
}

async function runPrompt(event) {
  event.preventDefault();
  if (busy || !config) return;
  error();
  try {
    const selected = settings();
    const mode = document.querySelector('input[name="mode"]:checked').value;
    setBusy(true);
    lastRun = null;
    $("results").replaceChildren();
    $("run-label").textContent = "Выполняется новый запрос";
    $("run-status").textContent = selected.provider === "ollama" ? "Модель готовит ответ… Сравнение может занять до двух минут." : "Выполняем запрос в тестовой базе…";
    const data = await request({ ...selected, mode, prompt: $("prompt").value, context: $("context").value });
    lastRun = { ui_session_version: 1, created_at: new Date().toISOString(), ...data };
    resultsInto($("results"), data.results);
    $("run-label").textContent = data.simulated ? "Симулятор · синтетические данные" : data.provider;
    $("run-status").textContent = "";
  } catch (err) {
    error(err.message || "Не удалось связаться с локальным сервером.");
    $("run-status").textContent = "Запрос не завершён.";
  } finally { setBusy(false); }
}

function createSuiteRows() {
  $("suite-rows").replaceChildren();
  for (const test of config.cases) {
    const row = node("tr");
    row.id = `case-${test.id}`;
    const name = node("td", "", titles[test.id] || test.title);
    name.append(node("span", "case-category", test.category));
    row.append(name, node("td", "muted", "—"), node("td", "muted", "—"), node("td"));
    $("suite-rows").append(row);
  }
}

function updateMetrics() {
  const findings = suite.findings;
  $("metric-cases").replaceChildren(document.createTextNode(String(suite.completed_cases) + " "), node("small", "", "/ 9"));
  for (const mode of ["vulnerable", "protected"]) {
    $(`metric-${mode}`).textContent = String(findings.filter((f) => f.mode === mode && f.outcome === "vulnerability").length);
  }
  $("metric-errors").textContent = String(findings.filter((f) => ["error", "failed", "inconclusive"].includes(f.outcome)).length);
  $("progress").value = suite.completed_cases;
}

async function runSuite() {
  if (busy || !config) return;
  error();
  try {
    const selected = settings();
    setBusy(true);
    createSuiteRows();
    $("suite-detail").hidden = true;
    suite = { ui_session_version: 1, created_at: new Date().toISOString(), provider: selected.provider, model: selected.model,
      simulated: selected.provider === "simulator", tenant: selected.tenant, complete: false, completed_cases: 0,
      scope: "Synthetic in-memory SQLite fixture only", findings: [] };
    updateMetrics();
    for (const test of config.cases) {
      $("suite-status").textContent = `${suite.completed_cases + 1} / 9 · ${titles[test.id] || test.title}${selected.provider === "ollama" ? " · ждём модель…" : ""}`;
      const data = await request({ ...selected, mode: "both", case_id: test.id });
      suite.findings.push(...data.results);
      suite.completed_cases += 1;
      const row = $(`case-${test.id}`);
      data.results.forEach((result, index) => row.children[index + 1].replaceChildren(badge(result.outcome)));
      const detail = node("button", "detail-button", "Детали ↗");
      detail.setAttribute("aria-label", `Детали: ${titles[test.id] || test.title}`);
      detail.addEventListener("click", () => {
        $("suite-detail").hidden = false;
        $("suite-detail-title").textContent = titles[test.id] || test.title;
        resultsInto($("suite-detail-results"), data.results);
        $("suite-detail").scrollIntoView({ block: "start", behavior: "auto" });
      });
      row.children[3].append(detail);
      updateMetrics();
    }
    suite.complete = true;
    $("suite-status").textContent = `Готово · 9 сценариев / 18 результатов · ${suite.simulated ? "симулятор" : selected.model}`;
  } catch (err) {
    error(err.message || "Не удалось связаться с локальным сервером.");
    $("suite-status").textContent = `Проверки прерваны · завершено ${suite?.completed_cases || 0} из 9. Доступны частичные результаты.`;
  } finally { setBusy(false); }
}

function download(data, filename) {
  if (!data) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
  const link = node("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function init() {
  setBusy(true);
  try {
    const response = await fetch("/api/config");
    if (!response.ok) throw new Error("Не удалось загрузить настройки сервера.");
    config = await response.json();
    $("version").textContent = `v${config.version}`;
    const quick = ["baseline-orders", "tenant-override", "private-column", "customer-sqli", "indirect-context"];
    for (const id of quick) {
      const test = config.cases.find((entry) => entry.id === id);
      const button = node("button", "scenario");
      button.append(node("span", "", titles[id]), node("span", "", "↗"));
      button.addEventListener("click", () => {
        $("prompt").value = test.prompt;
        $("context").value = test.retrieved_context;
        document.querySelector(".context-details").open = Boolean(test.retrieved_context);
        updateCount();
        $("prompt").focus();
      });
      $("scenario-list").append(button);
    }
    createSuiteRows();
    setBusy(false);
  } catch (err) { error(`${err.message} Перезапусти python -m queryguard ui и обнови страницу.`); }
}

document.querySelectorAll("[data-view]").forEach((button) => button.addEventListener("click", () => showView(button.dataset.view)));
$("provider").addEventListener("change", () => {
  const real = $("provider").value === "ollama";
  $("model-label").hidden = !real;
  $("provider-note").replaceChildren(node("span", "demo-tag", real ? "LOCAL LLM" : "DEMO"),
    node("span", "", real ? "Ollama должен быть запущен на 127.0.0.1:11434. Используется тестовая база." : "Готовые сценарии, без API-ключей. Это симулятор, а не настоящая LLM."));
});
$("prompt-form").addEventListener("submit", runPrompt);
$("prompt").addEventListener("input", updateCount);
$("prompt").addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === "Enter" && !busy) {
    event.preventDefault();
    $("prompt-form").requestSubmit();
  }
});
$("scan-button").addEventListener("click", runSuite);
$("download-run").addEventListener("click", () => download(lastRun, "queryguard-experiment.json"));
$("download-suite").addEventListener("click", () => download(suite, "queryguard-checks.json"));
updateCount();
init();
