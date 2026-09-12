# QDev CI: завершение инцидента на четырёх существующих VPS

Актуализировано 2026-09-12. Это исполнимый runbook для одного владельца
очереди и одного контроллера. Он заменяет исторические шаги активации и не
содержит адресов, секретных путей или ручных команд на хостах.

## 1. Подтверждённая стартовая точка

Публичный health-снимок от 2026-09-12 подтверждает:

- контроллер активен на `7433e4909bc92d23cc26fd3d6bf9fe939b99ebd8`;
- `controller_release` и `controller_activation` совпадают по SHA, а
  public/internal immutable image digests совпадают с release tuple;
- в очереди 30 заданий: 24 `qdev-ci`, 2 `qdev-ci-browser` и 4
  `qdev-ci-docker`;
- oldest pending age превышает 18 минут;
- безопасных допустимых слотов — 0 для обоих профилей.

Исходный `main` уже продвинулся до
`471f46b216a067da9380446259ef7a8332439d36`. Hosted recovery build для этого
точного SHA завершился успешно, однако нет runtime receipt его подписанной
активации: живой контроллер пока остаётся на `7433e49`. Непосредственная
причина простоя очереди — отсутствие хотя бы одного прошедшего аудит,
зарегистрированного и совместимого слота. Нельзя исправлять это отменой,
повторным dispatch, перестановкой FIFO или ручной заменой labels.

Исторический отменённый Platform job остаётся terminal. Его не воспроизводят;
ошибки тестов проектов после фактического старта фиксируются отдельно от
runner-инцидента.

## 2. Цель уровня 9/10

CI достигает 9/10, когда одновременно выполнены все условия:

1. Точный activation tuple остаётся `active` и связан с immutable release,
   public/internal images и подписанным ledger.
2. Есть минимум шесть безопасно допущенных слотов на трёх независимых VPS;
   четвёртый VPS прошёл аудит и остаётся N+1 reserve.
3. Ровно два хоста поддерживают `qdev-ci-docker`, максимум один Docker job на
   каждом; Platform-only runner не входит в общий пул.
4. Вся существующая очередь движется естественно в profile FIFO; нет
   дубликата, потери claim, requeue или старта на неправильном runner.
5. Прошли exact-SHA canary: `qdev-ci`, `qdev-ci-browser`, `qdev-ci-docker` и
   Platform recovery.
6. Watchdog каждые две минуты подтверждает переходы start/change/recovery и
   реально доставляет дедуплицированные уведомления ожидающим deployment-задачам
   только после старта соответствующего run/job.
7. В течение 24 часов после восстановления нет `activation unavailable`,
   stale claim, ошибки image digest, нарушения resource floor или head-of-queue
   SLO более 15 минут.

До окончания 24-часового soak состояние честно называется «восстановление
подтверждено», а не 10/10. Уровень 10/10 дополнительно требует успешного
rollback-drill без прерывания активных jobs и планирования мощности по семи
дням истории.

## 3. Каноническая ёмкость

Политика `qdev-ci-four-vps-capacity-v1` фиксирует только opaque
controller-registered identities. Она не содержит маршрутизируемых адресов и
не создаёт API для произвольного назначения хоста.

| Роль | Статус controller identity | Слоты после admission | Профили | Docker |
| --- | --- | ---: | --- | ---: |
| primary | зарегистрированная `srv1879763-primary` | 2 | ci, browser, docker | 1 |
| build | имя ещё не материализовано; допустим только tier `primary` | 2 | ci, browser, docker | 1 |
| general | имя ещё не материализовано; допустим только tier `primary` | 2 | ci, browser | 0 |
| N+1 reserve | имя ещё не материализовано; допустим только tier `reserve` | 2 | ci, browser | 0 |

Это намерение, не заявление о том, что все хосты уже работают. Плановый host ID
не является runner identity и не добавляет слот. Каждый слот учитывается только
после свежего signed host audit, проверенной runner registration/heartbeat,
controller-registry binding и resource admission. `qdev-platform-ci-187` сохраняет
свою отдельную contract identity и не забирает обычный проектный CI.

Единый контракт ресурсов:

- обычный worker: не менее 30 GiB свободно и не более 85% disk use;
- shared worker: не менее 10 GiB и не более 90%;
- точечное исключение: только `claim-scope-v2`, exact immutable job tuple,
  не менее 4.5 GiB, не более 90%, TTL не более 900 секунд;
- unscoped override и пороги 91%, 95%, 97% отвергаются.

## 4. Порядок исполнения

### R0 — сохранить доказательства и не трогать очередь

1. Снять signed incident receipt: health, activation/release tuple, current
   queue/claims, runner registrations, worker audits, temporary overrides и
   image digests.
2. Зафиксировать текущий active tuple как rollback anchor. Не останавливать
   активные jobs, не удалять runner registrations и не менять FIFO.
3. Работать из чистого checkout `origin/main`; пользовательские изменения и
   исторические detached checkout не использовать и не очищать.

### R1 — активировать подготовленный recovery-контур и допустить четыре VPS

Сначала root-side activation protocol должен установить ровно
`471f46b216a067da9380446259ef7a8332439d36` из успешно собранного immutable
artifact. До receipt, в котором `controller_release.revision`,
`controller_activation.source_revision` и оба image digest совпадают с этим
кандидатом, recovery ingress не вызывается и новые claims не выдаются.

После такой активации разрешён один узкий recovery-переход для уже
зарегистрированного `srv1879763-primary`: существующий hosted
`restore-existing-worker` ingress не принимает произвольные имя, labels,
host или tuple и восстанавливает только controller-recorded identity. Он не
создаёт второй runner и не меняет очередь.

Для каждого хоста, строго по одному:

1. В Hostinger/Comet выполнить read-only provider audit: ресурс существует,
   доступен, включён и не имеет provider/billing block. Никаких покупок,
   плановых изменений, DNS-изменений, бэкапов или перезапусков вне этого
   процесса.
2. Запросить signed host-agent audit через контроллер: CPU, memory, disk,
   PID/load, immutable runner image, heartbeat, existing claims и service
   identity.
3. Если active job есть — дождаться drain. Затем вернуть только сохранённую
   controller-managed конфигурацию, убрать только expired CI-temporary data
   или разрешённые неиспользуемые промежуточные слои и повторить audit.
4. Если пороги не выполнены, не открывать intake на этом хосте. Для primary
   после безопасной уборки ниже 40 GiB свободного места — увеличить уже
   существующий volume на 50 GiB либо перенести runner/BuildKit storage на
   отдельный volume не менее 120 GiB через provider + controller change
   receipt. Не применять general Docker prune и не удалять images, volumes,
   releases, базы или backups.
5. После успешного аудита восстановить только exact controller-registered
   worker identity и проверить GitHub labels against policy. Новый runner или
   label из operator input не принимается. Для `build`, `general` и `reserve`
   admission включает materialization identity через controller registry только
   после audit receipt; плановый host ID сам по себе registration не создаёт.

Порядок: `primary` → `build` → `general` → `reserve`. После первых трёх
прошедших аудитов доступно шесть слотов; reserve подключается по одному хосту
после FIFO wait >5 минут при здоровых занятых workers.

### R2 — открыть admission и восстановить движение очереди

1. Контроллер сверяет exact job tuple, profile, eligibility и FIFO перед каждым
   новым claim. Для новых/recovery claims допустим только `claim-scope-v2`.
2. Первый допустимый слот берёт голову соответствующего профиля. Primary и
   reserve могут работать параллельно, но reserve берёт только compatible
   profile head при отсутствии compatible primary slot.
3. Прогнать четыре canary на exact SHA. Каждый должен дать provider-terminal
   receipt с ожидаемым profile/runner; неправильный runner, mismatch SHA/digest,
   duplicate/lost job или resource-floor breach немедленно останавливает лишь
   новую выдачу claims и откатывает затронутый компонент.
4. После canary не «ускорять» очередь: наблюдать естественный start каждого
   pending job и отдельно фиксировать тестовые ошибки проекта.

### R3 — сделать повторение инцидента наблюдаемым

Watchdog запускается каждые две минуты и проверяет:

- `controller_activation != active` более двух минут;
- pending при нуле eligible slots более двух минут;
- oldest FIFO head: warning >5 минут, critical >15 минут;
- heartbeat старше 90 секунд, claim старше 300 секунд;
- disk/memory/load threshold, missing immutable image и provider/billing block.

Ключ дедупликации: `incident_id + state_digest + audience`. Разрешены только
start, существенное изменение и recovery. Watchdog формирует только durable
outbox и sealed reserve-decision; он сам не меняет очередь, runner labels,
host или provider state.

Delivery adapter должен забрать outbox, получить подтверждение доставки и
только после этого отправить связанной Codex deployment-задаче exact run/job и
реальный status. Это ещё незакрытый 9/10 gate: файл outbox не является
доставленным уведомлением. Сообщение «восстановлено» запрещено, пока её job
ещё queued. Heartbeat-монитор молчит при неизменном здоровом состоянии и
просыпается только на SLO breach, изменение или recovery.

## 5. Обязательная проверка изменений

Перед rollout выполняются только затронутые проверки:

- bootstrap policy: sealed four-VPS topology, запрет подмены host/roles/slots,
  Platform isolation и profile-to-label binding;
- admission: FIFO, profile concurrency, no-double-claim, restart/replay и
  offline exact-identity reconciliation without requeue;
- security: `claim-scope-v2` expiry/replay, OIDC failure, TTL >900 и отказ
  unscoped/91/95/97 overrides;
- capacity: primary/reserve offline, both busy, missing image, resource floor,
  one Docker job per host и drain without interrupting an active job;
- observability: alert start/change/recovery deduplication plus successful
  delivery adapter receipt;
- default-branch audit of active repositories: zero critical
  runner-label/fallback violations.

Публичные `/health` и `qdev-runner-health-v1` остаются обратно совместимыми:
только additive aggregate fields. Exact tuples, identities, host/audit/claim и
recovery details доступны исключительно на существующей mTLS internal surface.

## 6. Текущий прогресс и следующий безопасный переход

- Активация `7433e49`: завершена и подтверждена live health; переход на
  готовый `471f46b` ещё не имеет root-side activation receipt.
- Политика четырёх VPS: закреплена в исходном коде как sealed intent и покрыта
  targeted tests; до host audit она не считается доступной ёмкостью.
- Capacity admission, canaries и queue drain: ожидают подписанной активации
  `471f46b` и controller-managed host-agent receipts.
- Notification delivery: outbox/deduplication готов, но delivery adapter с
  receipt ещё не реализован; это не выдаётся за отправку сообщений.

Следующий переход — подписанная activation нового контроллера, затем
read-only inventory четырёх существующих VPS в Hostinger и signed audit
primary. Если любой из них не проходит, очередь остаётся нетронутой, а план
переключается на следующий уже существующий host; никаких самодельных runners,
новых VPS или обхода контроллера.
