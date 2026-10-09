# React2Shell Materials

Материалы и рабочие примеры по мотивам доклада **«Добро пожаловать на сервер: где в
Next.js App Router прячутся уязвимости»** (HolyJS, 23 октября 2026).

Разбор семейства уязвимостей **React2Shell** в Next.js App Router / React Server
Components — через архитектуру Flight-протокола и десериализатор `ReactFlightReplyServer`.

| CVE | Тип | Пример |
|-----|-----|--------|
| **CVE-2025-55182** | RCE через десериализацию Flight-пейлоада | [`exploits/cve-2025-55182-rce`](exploits/cve-2025-55182-rce) |
| **CVE-2025-55183** | Утечка исходного кода Server Function | [`exploits/cve-2025-55183-source-leak`](exploits/cve-2025-55183-source-leak) |
| **CVE-2025-55184** | DoS через циклические ссылки в чанках | [`exploits/cve-2025-55184-dos`](exploits/cve-2025-55184-dos) |

## Структура репозитория

### [vulnerable-target/](./vulnerable-target/)

**Уязвимое приложение-мишень.** Минимальный Next.js App Router, намеренно
зафиксированный на уязвимых версиях (Next 15.0.4, react-server-dom-webpack 19.0.2).
Серверный экшен `leakyAction` — цель для всех трёх эксплойтов. Поднимается на
`localhost:3000`, именно по нему стреляют PoC.

### [exploits/](./exploits/)

**Рабочие PoC по каждому CVE.** В каждой папке — свой `README` с описанием механики,
командой запуска и ожидаемым результатом:

- **[cve-2025-55182-rce/](./exploits/cve-2025-55182-rce/)** — RCE: сервер выполняет
  произвольный код (в демо — дамп `process.env`) (`poc-55182.js`).
- **[cve-2025-55183-source-leak/](./exploits/cve-2025-55183-source-leak/)** — утечка
  тела серверной функции в ответе (`poc-55183.js`).
- **[cve-2025-55184-dos/](./exploits/cve-2025-55184-dos/)** — DoS: поток сервера уходит
  в бесконечный цикл, CPU ~100% (`poc-55184.js`).

### [tools/server-action-audit/](./tools/server-action-audit/)

**Статический анализ кода Server Actions.** CLI, который читает AST ваших серверных экшенов и
показывает места, связанные с React2Shell (стрингинфай аргумента → 55183, захардкоженные секреты,
секрет через `.bind()`), плюс гигиену (мутации без auth/валидации, опасные sinks, mass assignment,
утечка через `return`). Это **не сканер версий** и **не доказательство уязвимости** — указатель,
куда посмотреть. Подробности и честный список ограничений — в [README тула](./tools/server-action-audit/).

## Быстрый старт

```bash
# 1. поднять уязвимую мишень
cd vulnerable-target
npm install
npm run dev            # http://localhost:3000

# 2. в другом терминале — выстрелить эксплойтом
cd exploits/cve-2025-55184-dos
npm install            # ставит form-data
node poc-55184.js
```

Подробности и ожидаемый вывод — в README каждого примера.

### Прогнать анализатор Server Actions

```bash
# на уязвимой мишени из этого репозитория (поймает leakyAction как HIGH)
npx github:startpointforl/react2shell-nextjs-materials ./vulnerable-target

# на своём проекте
npx github:startpointforl/react2shell-nextjs-materials ./path/to/your-app
```

## ⚠️ Дисклеймер

Это материалы для **образовательного доклада по безопасности**. Все уязвимости уже
исправлены в React и Next.js (см. [advisory React](https://react.dev/blog/2025/12/11/denial-of-service-and-source-code-exposure-in-react-server-components)).
Примеры запускаются **только против локального приложения-мишени из этого репозитория**
(`localhost`). Приложение `vulnerable-target` уязвимо by design и **не предназначено
для продакшена**.

## Первоисточники и ссылки

Общее по уязвимостям:
- [Advisory React](https://react.dev/blog/2025/12/11/denial-of-service-and-source-code-exposure-in-react-server-components) — официальный разбор DoS и утечки кода.
- [Фикс `toString()` в React](https://github.com/facebook/react/commit/894bc73cb493487c48d57f4508e6278db58e673a).
- [react2shell.com](https://react2shell.com).

По конкретным CVE:
- **CVE-2025-55182 (RCE)** — оригинальные PoC: [lachlan2k/React2Shell-CVE-2025-55182-original-poc](https://github.com/lachlan2k/React2Shell-CVE-2025-55182-original-poc).
- **CVE-2025-55183 (утечка кода)** — nuclei-шаблон для детекта: [kimtruth/CVE-2025-55183-poc](https://github.com/kimtruth/CVE-2025-55183-poc).

## 🤝 Автор

**Настя Котова** — [@startpoint_dev](https://t.me/startpoint_dev)
Фронтендер с лапками
