# QDev CI: завершение инцидента на четырёх существующих VPS

Актуализировано 2026-09-12 после свежего live health-снимка, sealed hosted
recovery build №76 и переноса проверенного source-кандидата на текущий
`origin/main`. Это
исполнимый runbook для одного владельца очереди и одного контроллера. Он
заменяет исторические шаги активации и не содержит адресов, секретных путей
или ручных команд на хостах.

## 1. Подтверждённая стартовая точка

Публичный health-снимок от 2026-09-12 подтверждает:

- контроллер активен на `7433e4909bc92d23cc26fd3d6bf9fe939b99ebd8`;
- `controller_release` и `controller_activation` совпадают по SHA, а
  public/internal immutable image digests совпадают с release tuple;
- `controller_activation` active на generation `15`;
- `pending=29`, oldest pending age — `6 183` секунды;
- `eligible_slots.primary=0`, `eligible_slots.reserve=0` и total `0`; primary
  отсутствует в live view, reserve виден, но не предоставляет слот;
- public health намеренно не раскрывает profile split. Историческое
  распределение 20/2/9 нельзя использовать как текущий факт без нового
  signed internal receipt.

На момент актуализации `origin/main` уже продвинулся до
`2ba23702fd76036a0de7d59c4d91a6db50988970`. Чистый recovery-кандидат
`1808eceb480a7ff311b458f037e1b5a641bd798d` перенесён на этот commit без
конфликтов; затронутый набор controller, capacity, delivery и audit-проверок
прошёл `290 passed`, formatter/linter/diff check чистые. Hosted recovery build №76 для
исторического SHA `800e30cba32b032cb7a43182eaf3a2b5ee7201c5` завершился
успешно; sealed artifact
`controller-recovery-800e30cba32b032cb7a43182eaf3a2b5ee7201c5` имеет digest
`sha256:ae583c51277a009cfecf11fa83a9c052f2e3a2f8e7167c8c5853f8c9f8de2a4d`.
Это историческое build-доказательство, а не незавершённый rollout: текущий
`7433e49` уже имеет совпадающий release/activation tuple и остаётся baseline
на время восстановления ёмкости. Кандидат на основе текущего `2ba2370` не активируется
автоматически: для него сначала нужны собственные immutable artifact,
signature/provenance и activation receipt. Непосредственная причина простоя очереди —
отсутствие хотя бы одного прошедшего аудит, зарегистрированного и совместимого
слота. Нельзя исправлять это отменой, повторным dispatch, перестановкой FIFO
или ручной заменой labels.

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
rollback-drill без прерывания активных jobs и weekly review результата
семидневного profile-scoped capacity planner.

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

### R1 — закрыть исторические activation-транзакции без смены runtime и допустить четыре VPS

Перед host-операциями root-side reconciler читает существующие R1/R2
transaction IDs и проверяет текущие runtime SHA, public/internal image digests,
release link, health и staged material. Для уже active `7433e49` он обязан
выдать idempotent reconciliation receipt без mutation (`finalized` или
`already-finalized`); `resolved_no_mutation` применим только к historical R2
record. Повторная активация build №76, replay истёкшего envelope или rollback
на historical anchor запрещены.
Несовпадающая либо отсутствующая цепочка завершается fail-closed без смены
runtime и без новой выдачи claims. Детали остаются в mTLS receipt; public
health сохраняет только additive aggregates.

После такого reconciliation разрешён один узкий recovery-переход для уже
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

Текущий внешний prerequisite для R1 узкий: нужна доступная authenticated
operator-сессия Hostinger/Comet. После прямого входа оператора сначала
выполняется только read-only mapping четырёх уже известных VPS, затем —
описанные controller-managed переходы; эта задача не запрашивает и не
обрабатывает учётные данные или 2FA-коды.

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
outbox и sealed reserve-decision. Решение reserve хранится как pending request,
а не как activated capacity: его перевод возможен только по точному signed
host-agent receipt. Watchdog сам не меняет очередь, runner labels, host или
provider state.

Подготовленный source-кандидат receipt-bound delivery
меняет этот контур на receipt-bound delivery: `job-delivery-outbox.json`
содержит стабильный `delivery_id`, pending tuple сначала сохраняется в
root-only ledger, и только строго совпадающий root-only receipt переводит его
в acknowledged. Это исключает ложное «уведомлено» при падении адаптера или
сбое между записью outbox и отправкой. Целевые tests и lint пройдены локально;
его не отправляют в GitHub до появления первого compatible slot, чтобы не
создавать ещё один self-hosted job в уже заблокированной очереди.

После восстановления первого слота fixed root-owned delivery adapter должен
забрать этот outbox, получить подтверждение доставки и только после этого
отправить связанной Codex deployment-задаче exact run/job и реальный status.
До этого это незакрытый 9/10 gate: файл outbox не является доставленным
уведомлением. Сообщение «восстановлено» запрещено, пока её job ещё queued.
Исполнитель доставки также ведёт ограниченный retry (120 и 300 секунд) и
помещает ambiguous/permanent result в root-only DLQ. Его агрегатный размер
теперь является отдельным critical watchdog breach; наружу уходит только код
инцидента, а job tuple остаётся локальным для reconciliation. Это исключает
как дубликат после неопределённой отправки, так и молчаливую потерю сообщения.
Heartbeat-монитор молчит при неизменном здоровом состоянии и просыпается
только на SLO breach, изменение или recovery.

Отдельный read-only collector теперь формирует
`qdev-ci-profile-history-v1` непосредственно из controller store: это ровно
168 complete UTC-hour buckets только для sealed profiles и длительности лишь
завершённых claims. Он открывает SQLite только в read-only режиме, отвергает
symbolic-link и group/world-writable database и не выводит repository, job,
runner, host или claim data. На его входе review-only
`qdev-ci-capacity-plan-v1` рассчитывает по каждому профилю
`ceil(p95 hourly arrivals × p95 duration minutes / 60 / 0.7)`. При
отсутствующей или неполной семидневной истории он сохраняет baseline `6 + 2`,
а при результате более восьми registered slots требует human/controller
capacity review. Ни collector, ни planner не имеют provider, runner или queue
mutation path.

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

- Активация `7433e49`: завершена и подтверждена live health. Sealed build
  №76 для `800e30c` сохранён как historical build evidence; он не является
  gate для текущего capacity recovery и не должен активироваться повторно.
- Политика четырёх VPS: закреплена в исходном коде как sealed intent и покрыта
  targeted tests; до host audit она не считается доступной ёмкостью.
- Capacity admission, canaries и queue drain: ожидают reconciliation receipt
  для historical transactions и controller-managed host-agent receipts. На
  последнем public health-снимке `pending=29`, oldest age — `6 183` секунды,
  а eligible slots остаются нулевыми для primary и reserve. Profile split
  недоступен на этой public surface. Изменение числа pending само по себе не
  является восстановлением capacity и не даёт оснований для сообщения
  ожидающим deployment-задачам.
- Notification delivery, reserve accounting и capacity planner: receipt-bound
  source-кандидаты локально готовы; reserve больше не может быть ложно отмечен
  активным при одной лишь записи watchdog. Watchdog уже materializes stable
  sealed request в root-only outbox и принимает только exact capacity receipt:
  host, request id, two non-Docker slots, timestamp и audit digest. Receipt
  старше 300 секунд либо с недопустимым clock skew теперь fail-closed и не
  может отметить reserve активным. Blocked receipt остаётся terminal и не
  запускает автоматический retry.
  Новый sealed root-owned reserve executor уже добавлен локально: он принимает
  только этот controller-owned request для `mail-general-reserve`, сверяет
  private registry binding с фиксированным adapter path, требует свежий audit
  до append-only receipt и не вызывает adapter повторно после exact replay.
  В нём нет свободного shell, runner name, labels или host address из operator
  input. Executor встроен в обычный controller release/provisioning: path unit
  ставится вместе с immutable release, но service не стартует без root-private
  registry binding. Это покрыто 99 targeted tests и static check локально;
  последние source commits — `f17d7f9`, `a41a899` и `898fba5` в отдельном
  чистом worktree.
  Отдельный `qdev_capacity_history_collector.py` теперь materialized в том же
  чистом source candidate: он выдаёт sealed seven-day input для planner без
  нового API или фоновой мутации. Вместе с ним controller provisioning и
  immutable activation устанавливают root-only weekly
  `qdev-capacity-plan.timer`: он читает только local `broker.db`, пишет только
  aggregate plan в `/var/lib/qdev-runner/capacity` и не имеет provider, runner,
  queue, registry или admission path. История остаётся неполной до первого
  фактического run после R1 receipt; это не мешает fixed baseline `6 + 2`, но
  запрещает выдавать расчёт за наблюдённую нагрузку.
  Отдельный `qdev_default_branch_audit.py` materialized в том же candidate:
  он перед scan заново сверяет repository identity и default branch через
  provider API, фиксирует точный resolved commit SHA и только затем вызывает
  существующий workflow auditor. Поэтому устаревшее имя ветки из inventory не
  может выдать label/fallback audit за актуальный. Focused audit tests прошли
  локально; live provider scan остаётся после появления первого compatible
  slot, чтобы не расходовать provider quota при нулевой capacity.
  Исполнитель task-delivery materialized в source-кандидате `b74ee33` и его
  DLQ escalation — в `2129cfb`. Эти изменения перенесены без конфликтов на
  текущий `origin/main`; implementation head чистого кандидата —
  `1808eceb480a7ff311b458f037e1b5a641bd798d`, и в нём находится этот
  актуальный runbook. Общий целевой набор controller, capacity, delivery,
  watchdog, planner, default-branch audit, claim scope, FIFO admission, fleet
  dispatch, worker recovery, four-host bootstrap и независимого QazPolit
  artifact binding прошёл `290 passed`; formatter, linter и diff check также
  чистые.
  Кандидат намеренно не опубликован:
  при нулевых eligible slots push создал бы ещё одну заблокированную
  self-hosted задачу и не приблизил восстановление. Не
  materialized остаются только реальный task-delivery adapter с root-owned
  mapping и private registry binding к уже существующему host-agent. Поэтому
  ни одно сообщение и ни один VPS не выдаются за фактически активированные,
  а планировщик не может сам активировать host или выдать claim.
- Hosted build №76 завершился с provider warning о переходе GitHub Actions с
  Node.js 20 на Node.js 24 для двух pinned actions. Это не блокирует текущий
  runtime; обновление pinned action revisions — отдельная проверяемая
  hardening-задача после восстановления capacity.

Следующий переход — idempotent reconciliation текущего activation ledger,
затем read-only inventory четырёх существующих VPS в Hostinger и signed audit
primary. Если любой из них не проходит, очередь остаётся нетронутой, а план
переключается на следующий уже существующий host; никаких самодельных runners,
новых VPS или обхода контроллера.
