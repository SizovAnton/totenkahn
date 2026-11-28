# Totenkahn v0.1.0

Локальна платформа Evidence / Hunting / Detection Validation. Цей посібник описує поточні команди та межі їхніх результатів; наявність функції не означає приймання всіх джерел і сценаріїв.

## Стан MVP v0.1.0

Межі приймання: живий тест не перевіряв EDR-алерти або всі сценарії Atomic; реальне приймання Splunk у цьому циклі не підтверджене. Rollback перевірено між двома збірками одного коміту, без міграцій даних. Тег і публікація GitHub Release — окремі кроки; готовність коду не означає наявності опублікованого релізу. Подробиці: [опис v0.1.0](docs/RELEASE_NOTES_v0.1.0.md).

## Встановлення та перший запуск

### 1. Отримайте повний Windows-пакет

Для запуску готової Windows-збірки не потрібно встановлювати Python, pip чи редагувати код. Python і бібліотеки застосунку входять до пакета. Потрібні Windows x64 та PowerShell; для завантаження відсутніх базових модулів потрібен інтернет або заздалегідь підготовлений кеш. Окремі live-операції потребують адміністративних прав і налаштованої телеметрії; запуск перегляду та офлайн-аналіз не вимагає автоматичного підвищення прав.

Використовуйте ZIP із перевіреного GitHub Release, коли його опубліковано. До публікації джерело пакета — артефакт **TOTENKAHN Windows candidate** з прийнятого build run:

- `totenkahn-windows-candidate-<COMMIT>.zip` — зовнішній архів GitHub; спочатку розпакуйте його;
- усередині — `totenkahn-windows-candidate.zip`, контрольні суми та звіти;
- `ci-windows-…zip` і `windows-diagnostics-…zip` містять діагностику, а не готову програму;
- GitHub **Source code (zip)** — вихідний код, а не пакет із `.exe`.

Приклад нижче припускає, що внутрішній `totenkahn-windows-candidate.zip` уже знаходиться в `C:\Downloads`. Порівняйте його хеш із `ZIP SHA-256` у довіреному build run або контрольними сумами прийнятого релізу:

```powershell
Get-FileHash -LiteralPath 'C:\Downloads\totenkahn-windows-candidate.zip' -Algorithm SHA256
```

Продовжуйте лише після збігу хешу. SHA-256 захищає від непоміченої зміни байтів, але сам по собі не є підписом видавця.

### 2. Розпакуйте програму

Для першого знайомства достатньо portable-розміщення: повний пакет розпаковується в окремий каталог. Не копіюйте один `.exe` без супровідних файлів і не накладайте нову збірку поверх старої.

```powershell
Expand-Archive -LiteralPath 'C:\Downloads\totenkahn-windows-candidate.zip' -DestinationPath 'C:\Totenkahn'
Set-Location 'C:\Totenkahn'
Test-Path -LiteralPath '.\totenkahn.exe'
Test-Path -LiteralPath '.\totenkahn-setup.exe'
```

Обидві перевірки повинні повернути `True`. Якщо `C:\Totenkahn` уже зайнятий, оберіть новий порожній каталог. Встановлення як служби, реєстрація команди в PATH і зміна системних політик при розпакуванні не виконуються. Для керованих оновлень з активацією та rollback використовуйте [розділ 28](#28-cd-доставка-активація-та-rollback).

У термінал копіюйте тільки команди всередині блоків, без рядків із трьома зворотними лапками та словом `powershell`.

### 3. Підготуйте базові залежності

Для імпорту дампів та інших офлайн-операцій Atomic не потрібен. Для роботи з Atomic підготуйте базові модулі. У звичайній дозволеній лабораторній конфігурації Windows PowerShell спочатку встановіть політику лише для поточного процесу:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force
```

Ця настройка діє в поточному вікні PowerShell; після відкриття нового вікна її може знадобитися повторити. Вона не перевизначає корпоративну Group Policy. Якщо організаційна політика забороняє сценарії, перевірте діагностику й узгодьте дозволений спосіб із адміністратором.

Підготовка однією командою:

```powershell
.\totenkahn.exe dependencies prepare
```

Програма шукає наявні компоненти, перевіряє їхню сумісність, показує план і запитує згоду. Придатні зовнішні компоненти використовуються без перезаписування; відсутні керовані базові модулі завантажуються та перевіряються. Для вже погодженого виконання без запитання:

```powershell
.\totenkahn.exe dependencies prepare --yes
```

`-y` — короткий варіант `--yes`. На цьому кроці готуються `powershell_yaml` та `invoke_atomic_red_team`. Визначення, ресурси й передумови конкретного Atomic-тесту готуються окремо для вибраного сценарію; весь набір payloads не встановлюється наперед. Наявне Atomic у нестандартному каталозі можна вказати через `--atomic-dir` — деталі в розділі 22.

Без інтернету використовуйте підготовлений перевірений кеш:

```powershell
.\totenkahn.exe dependencies prepare --offline --cache 'C:\Packages\TotenkahnCache'
```

**Що перевірити:** статус кожного компонента та причини `needs_verification`/помилок. Відсутній пакет у кеші не означає успішного встановлення. Не вимикайте захист для приховування помилок: збережіть діагностику й використовуйте доступні можливості платформи.

### 4. Перевірте перший запуск

```powershell
.\totenkahn.exe --help
.\totenkahn.exe dump profiles
.\totenkahn.exe doctor --mode replay
.\totenkahn.exe dependencies status
```

Очікуємо банер `v0.1.0`, перелік профілів та зрозумілі результати перевірки середовища. `doctor --mode replay` не сертифікує live-збір чи Atomic. Команди довідки та профілів не встановлюють залежності автоматично. Перший `test auto` також може запропонувати підготовку відсутніх компонентів, але це не замінює перевірку результатів їх встановлення.

За бажанням виконайте повний офлайн-самотест у новому каталозі:

```powershell
.\totenkahn.exe self-test offline --output-dir 'C:\TotenkahnReports\first-run-01'
```

**Що перевірити:** усі п'ять етапів мають пройти. Каталог результатів має бути новим; для повтору використайте, наприклад, `first-run-02`. Самотест використовує синтетичні дані, не виконує Atomic та не підключається до SIEM/EDR.

### 5. Де зберігаються дані та як видалити програму

Стандартні дані користувача зберігаються в `%LOCALAPPDATA%\totenkahn`; змінна `TOTENKAHN_HOME` задає інший каталог. Результати з явним `--output-dir` зберігаються за вказаним шляхом. Каталог програми, докази та delivery store не слід змішувати.

Перед видаленням керованих залежностей перегляньте план:

```powershell
.\totenkahn.exe dependencies remove --dry-run
```

Після погодження:

```powershell
.\totenkahn.exe dependencies remove --yes
```

Видалення враховує облік власності: зовнішні або змінені файли не повинні видалятися як незмінні керовані компоненти; перегляньте список збережених залишків. Ця команда не видаляє portable-каталог програми та не скасовує виконані Atomic-дії або зміни аудиту. Після завершення роботи portable-каталог можна видалити окремо, попередньо зберігши власні файли. Дані й докази не видаляйте разом із програмою. Для встановлення через setup використовуйте відповідний механізм uninstall; не змішуйте його облік із portable або delivery-сховищем.


## Загальні позначення

Команди наведено для PowerShell із каталогу, де розташований `totenkahn.exe`.

- `<RULE_PATH>`, `<SOURCE>` та інші значення в кутових дужках потрібно замінити власними.
- `[OPTIONS]` означає необов’язкові параметри; квадратні дужки вводити не потрібно.
- Файли правил, контексту й очікувань у прикладах мають існувати заздалегідь.
- Відносні шляхи обчислюються від поточного каталогу термінала.

## 1. Автоматичний тест

Виконує вибраний Atomic Red Team тест, збирає Windows-події та перевіряє їх Sigma-правилом. Інженер отримує результати виконання дії, збору телеметрії та перевірки детекції.

### Основний запуск

Використовується для перевірки правила на контрольованій дії у тестовому Windows-середовищі.

**Синтаксис:**

```powershell
.\totenkahn.exe test auto --rule "<RULE_PATH>" --technique <TECHNIQUE_ID> <TEST_NUMBER> [OPTIONS]
```

**Приклад:**

```powershell
.\totenkahn.exe test auto --rule "C:\Rules\whoami.yaml" --technique T1033 8
```

`--rule` задає Sigma-правило, а `--technique` — ID техніки та номер тесту. Платформа перевіряє готовність середовища й запитує необхідні дозволи перед змінами та виконанням.

**Що перевірити:** у блоці `Atomic lifecycle` окремо перегляньте `Test execution`, `Collection` і `Rule result`. Успішне виконання команди не означає, що правило виявило дію; звірте також докази, на яких ґрунтується рішення.

### Перевірка готовності без запуску

Дає змогу заздалегідь побачити проблеми телеметрії та базових залежностей, не змінюючи систему й не виконуючи тест.

**Синтаксис:**

```powershell
.\totenkahn.exe test auto --rule "<RULE_PATH>" --technique <TECHNIQUE_ID> <TEST_NUMBER> --plan
```

**Приклад:**

```powershell
.\totenkahn.exe test auto --rule "C:\Rules\whoami.yaml" --technique T1033 8 --plan
```

**Що перевірити:** у результаті `Readiness plan` перегляньте стан телеметрії, базових залежностей і причини блокування. План не перевіряє всі передумови вибраного Atomic-тесту, тому не підтверджує його повну готовність.

### Передавання параметрів тесту

Дозволяє змінити передбачені тестом аргументи без редагування його визначення. Інженер отримує запуск із потрібними значеннями, наприклад іншими аргументами команди.

**Синтаксис:**

```powershell
.\totenkahn.exe test auto --rule "<RULE_PATH>" --technique <TECHNIQUE_ID> <TEST_NUMBER> --input "NAME=VALUE"
```

**Приклад:**

```powershell
.\totenkahn.exe test auto --rule "C:\Rules\whoami.yaml" --technique T1033 8 --input "whoami_args=/all"
```

Для кількох параметрів повторіть `--input`. Назви мають відповідати визначенню тесту.

**Що перевірити:** перед запуском звірте сформовану команду; після запуску — фактичний командний рядок у доказах і значення полів, які перевіряє Sigma. Це підтверджує, що аналізувався потрібний варіант дії.

### Обмеження часу виконання

Запобігає необмеженому очікуванню завершення Atomic-команди. Інженер отримує контрольований результат завершення або тайм-аут.

**Синтаксис:**

```powershell
.\totenkahn.exe test auto --rule "<RULE_PATH>" --technique <TECHNIQUE_ID> <TEST_NUMBER> --timeout <SECONDS>
```

**Приклад:**

```powershell
.\totenkahn.exe test auto --rule "C:\Rules\whoami.yaml" --technique T1033 8 --timeout 60
```

Типове значення — `120` секунд, діапазон — `1–3600`. Це тайм-аут Atomic-команди, а не всього процесу підготовки й аналізу.

**Що перевірити:** статус кроку `Execute test`, причину завершення та стан `Collection`. Результат перерваного виконання не слід трактувати як повністю проведений тест.

### Підготовка передумов

Дозволяє виконати передбачені тестом команди підготовки, якщо потрібних передумов немає. Інженер отримує окремі результати початкової перевірки, підготовки та повторної перевірки.

**Синтаксис:**

```powershell
.\totenkahn.exe test auto --rule "<RULE_PATH>" --technique <TECHNIQUE_ID> <TEST_NUMBER> --prepare-prereqs
```

**Приклад:**

```powershell
.\totenkahn.exe test auto --rule "C:\Rules\whoami.yaml" --technique T1033 8 --prepare-prereqs
```

**Що перевірити:** кроки `Check prerequisite`, `Prepare prerequisite` і `Recheck prerequisite`, якщо вони присутні. Підготовка передумов не є виконанням самого тесту й не підтверджує детекцію.

### Очищення після тесту

Виконує очищення, визначене автором вибраного Atomic-тесту. Інженер отримує інформацію про виконання cleanup і можливі залишкові зміни.

**Синтаксис:**

```powershell
.\totenkahn.exe test auto --rule "<RULE_PATH>" --technique <TECHNIQUE_ID> <TEST_NUMBER> --cleanup
```

**Приклад:**

```powershell
.\totenkahn.exe test auto --rule "C:\Rules\whoami.yaml" --technique T1033 8 --cleanup
```

**Що перевірити:** `Cleanup`, відповідний крок lifecycle і пояснення невиконаного очищення. Успішний cleanup не гарантує повного відновлення хоста.

Для явної згоди на всі підтвердження обраного сценарію використовуйте `-y` або `--yes`:

```powershell
.\totenkahn.exe test auto --rule C:\Rules\whoami.yaml --technique T1033 8 -y
.\totenkahn.exe dependencies prepare --yes
.\totenkahn.exe telemetry restore -y
.\totenkahn-setup.exe uninstall -y
```

У `test auto` цей прапорець погоджує базові залежності, вибрані ресурси, потрібні зміни телеметрії та виконання вибраного Atomic-плану, включно з перевірками передумов. У `test manual` — потрібні зміни телеметрії; Enter для завершення ручного збору залишається необхідним. У replay прапорець не додає жодних дій. У командах dependencies/telemetry/uninstall він погоджує лише запитану операцію. У старому `--auto` погоджує базові залежності та вибраний Atomic-план. `--plan`, `--atomic-plan` і `--dry-run` залишаються переглядом без виконання. Прапорець не вмикає `--prepare-prereqs`, `--cleanup`, не приймає Sysmon EULA і не обходить перевірки готовності чи політики хоста.

### Попереднє надання дозволів

Призначене для запуску заздалегідь перевіреного сценарію без інтерактивних підтверджень. Дозволи залишаються розділеними за типом дії.

| Опція | Що дозволяє |
|---|---|
| `--approve-dependencies` | Підготовку базових модулів і ресурсів вибраного тесту. |
| `--approve-telemetry` | Показані зміни налаштувань телеметрії хоста. |
| `--approve-atomic` | Виконання вибраного Atomic-плану та перевірок передумов. |
| `--prepare-prereqs` | Додатково — виконання коду встановлення передумов. |

**Синтаксис:**

```powershell
.\totenkahn.exe test auto --rule "<RULE_PATH>" --technique <TECHNIQUE_ID> <TEST_NUMBER> --approve-dependencies --approve-telemetry --approve-atomic
```

**Приклад:**

```powershell
.\totenkahn.exe test auto --rule "C:\Rules\whoami.yaml" --technique T1033 8 --approve-dependencies --approve-telemetry --approve-atomic
```

**Що перевірити:** результати `Base dependencies`, `Selected resources`, `Telemetry readiness` і `Atomic lifecycle`. Прапорець дозволу не означає успішного виконання відповідного кроку.

### Використання локальних пакетів

Дає змогу підготувати тест без завантаження пакетів із мережі. Інженер отримує перевірку доступності необхідних локальних ресурсів і кешу.

**Синтаксис:**

```powershell
.\totenkahn.exe test auto --rule "<RULE_PATH>" --technique <TECHNIQUE_ID> <TEST_NUMBER> --offline
```

**Приклад:**

```powershell
.\totenkahn.exe test auto --rule "C:\Rules\whoami.yaml" --technique T1033 8 --offline
```

Якщо потрібне встановлення відсутнього Sysmon, надайте локальний офіційний архів і підтвердьте прийняття ліцензії:

```powershell
.\totenkahn.exe test auto --rule "C:\Rules\whoami.yaml" --technique T1033 8 --offline --sysmon-archive "C:\Packages\Sysmon.zip" --accept-sysmon-eula
```

Згода на зміни телеметрії надається окремо. `--offline` обмежує завантаження пакетів, але не мережеві дії самого тесту.

**Що перевірити:** відсутні або заблоковані ресурси, результати перевірки локальних пакетів і готовність телеметрії.

### Додаткові ресурси тесту

Використовується, коли динамічне посилання на ресурс неможливо визначити автоматично. Інженер явно включає перевірений файл або ресурсну папку техніки до підготовки.

**Синтаксис:**

```powershell
.\totenkahn.exe test auto --rule "<RULE_PATH>" --technique <TECHNIQUE_ID> <TEST_NUMBER> --asset-file "<RESOURCE_PATH>" --asset-technique "<RESOURCE_TECHNIQUE_ID>"
```

**Шаблон застосування для власного тесту:**

```powershell
.\totenkahn.exe test auto --rule "C:\Rules\custom-test.yaml" --technique <TECHNIQUE_ID> <TEST_NUMBER> --asset-file "<REVIEWED_RESOURCE_PATH>"
```

`--asset-file` і `--asset-technique` можна повторювати. Конкретні значення беруться з перевіреного визначення тесту; універсального ресурсного файла для всіх тестів немає.

**Що перевірити:** склад `Selected resources`, результати перевірки файлів і причини відхилення. Додавання ресурсів не означає запуск додаткових тестів.

### Деталізація й кореляція

Допомагає пояснити проблеми підготовки та перевірити, які події пов’язані з тестовою дією.

**Синтаксис:**

```powershell
.\totenkahn.exe test auto --rule "<RULE_PATH>" --technique <TECHNIQUE_ID> <TEST_NUMBER> [-v | -vv] [--show-correlation]
```

**Приклад:**

```powershell
.\totenkahn.exe test auto --rule "C:\Rules\whoami.yaml" --technique T1033 8 -vv --show-correlation
```

`-v` розширює повідомлення підготовки, `-vv` показує повні технічні дані preflight, `--show-correlation` — подробиці доступних зв’язків подій.

**Що перевірити:** причини неготовності, ідентифікатори процесів, батьківські зв’язки й підстави прив’язки до запуску. Збіг сторонньої події не підтверджує виявлення тесту.

## 2. Ручний тест

Збирає Windows-події під час дій, які виконує інженер, і перевіряє їх Sigma-правилом. Використовується для власних сценаріїв без запуску Atomic Red Team.

### Основний запуск

Дає змогу перевірити реальну ручну дію та зберегти її телеметрію для повторного аналізу.

**Синтаксис:**

```powershell
.\totenkahn.exe test manual --rule "<RULE_PATH>" [OPTIONS]
```

**Приклад:**

```powershell
.\totenkahn.exe test manual --rule "C:\Rules\whoami.yaml"
```

Після перевірки готовності:

1. Дочекайтеся початку збору.
2. В іншому вікні виконайте потрібну дію, наприклад:

   ```powershell
   whoami.exe /all
   ```

3. Поверніться до Totenkahn і натисніть `Enter`.
4. Перегляньте результат аналізу.

**Що перевірити:** стан збору, часовий інтервал, наявність очікуваних подій і рішення правила. `Enter` завершує збір, але не підтверджує виконання запланованої дії.

### Перевірка готовності

Дозволяє виявити проблеми джерела подій до початку ручного сценарію без зміни налаштувань.

**Синтаксис:**

```powershell
.\totenkahn.exe test manual --rule "<RULE_PATH>" --plan
```

**Приклад:**

```powershell
.\totenkahn.exe test manual --rule "C:\Rules\whoami.yaml" --plan
```

**Що перевірити:** стан телеметрії, необхідні зміни й причини блокування. Готова конфігурація ще не доводить надходження потрібних подій.

### Опис дії та очікуваного результату

Пов’язує ручний сценарій із підготовленим контекстом і очікуваннями. Інженер отримує оцінку очікуваного результату, а не лише список збігів.

**Синтаксис:**

```powershell
.\totenkahn.exe test manual --rule "<RULE_PATH>" --test-context "<CONTEXT_JSON>"
```

**Приклад:**

```powershell
.\totenkahn.exe test manual --rule "C:\Rules\whoami.yaml" --test-context "C:\Tests\whoami-context.json"
```

JSON має відповідати контракту ручного тесту Totenkahn: опис `description`, необов’язкові `notes` та `expected_rule_match` (true, false або null). Він описує сценарій, але не виконує дії; очікування стосується всіх подій сесії (`all_session_events`), а не автоматично виділеної дії.

**Що перевірити:** задане очікування, його фактичний результат, достатність даних і підстави відбору доказів. Збіг десь у сесії не завжди означає виявлення саме ручної дії.

### Попереднє погодження телеметрії

Прибирає окремий запит дозволу на показані зміни телеметрії. Сам збір залишається ручним і завершується через `Enter`.

**Синтаксис:**

```powershell
.\totenkahn.exe test manual --rule "<RULE_PATH>" --approve-telemetry
```

**Приклад:**

```powershell
.\totenkahn.exe test manual --rule "C:\Rules\whoami.yaml" --approve-telemetry
```

**Що перевірити:** результат підготовки та повторну перевірку `Telemetry readiness`. Наявність дозволу не підтверджує успішність змін.

### Підготовка без мережевого завантаження

Використовується в середовищі з локальними пакетами. Інженер отримує готовність телеметрії без завантаження інсталяційних файлів.

**Синтаксис:**

```powershell
.\totenkahn.exe test manual --rule "<RULE_PATH>" --offline [--sysmon-archive "<ARCHIVE_PATH>" --accept-sysmon-eula]
```

**Приклад для вже підготовленого хоста:**

```powershell
.\totenkahn.exe test manual --rule "C:\Rules\whoami.yaml" --offline
```

**Приклад із локальним Sysmon:**

```powershell
.\totenkahn.exe test manual --rule "C:\Rules\whoami.yaml" --offline --sysmon-archive "C:\Packages\Sysmon.zip" --accept-sysmon-eula
```

**Що перевірити:** чи потрібне встановлення Sysmon, чи прийнято локальний пакет і чи пройдено повторну перевірку телеметрії.

### Деталізація підготовки

Допомагає з’ясувати причину неготовності джерела перед ручним сценарієм. Параметр `--show-correlation` приймається CLI, але окремий термінальний перегляд кореляції автоматичних запусків для ручних сесій не виводиться.

**Синтаксис:**

```powershell
.\totenkahn.exe test manual --rule "<RULE_PATH>" [-v | -vv]
```

**Приклад:**

```powershell
.\totenkahn.exe test manual --rule "C:\Rules\whoami.yaml" -vv
```

**Що перевірити:** діагностику джерела та причини неготовності; після збору — фактичні значення подій і контекст ручного тесту. Сам часовий збіг не доводить зв’язку події з дією.

## 3. Повторний аналіз збереженої сесії

Перевіряє Sigma-правило на збережених подіях без нового збору та повторного виконання дій. Інженер може уточнювати правило, використовуючи незмінні вхідні докази.

### Основний запуск

Використовується для повторної перевірки раніше зібраної сесії.

**Синтаксис:**

```powershell
.\totenkahn.exe test replay --rule "<RULE_PATH>" --session "<SESSION_DIRECTORY>" [OPTIONS]
```

**Приклад:**

```powershell
.\totenkahn.exe test replay --rule "C:\Rules\whoami.yaml" --session "C:\Evidence\whoami-session"
```

Каталог сесії має містити `events.json`. Для наборів, створених через `dump import`, використовується `dump analyze`.

**Що перевірити:** використане правило, вибрану сесію, кількість проаналізованих подій, рішення правила та пояснення перевірок. Replay не підтверджує поточну готовність live-телеметрії.

### Перевірка іншої версії правила

Дозволяє оцінити зміну логіки правила без повторного створення подій.

**Синтаксис:**

```powershell
.\totenkahn.exe test replay --rule "<UPDATED_RULE_PATH>" --session "<SAME_SESSION_DIRECTORY>"
```

**Приклад послідовної перевірки:**

```powershell
.\totenkahn.exe test replay --rule "C:\Rules\whoami-v1.yaml" --session "C:\Evidence\whoami-session"
```

```powershell
.\totenkahn.exe test replay --rule "C:\Rules\whoami-v2.yaml" --session "C:\Evidence\whoami-session"
```

**Що перевірити:** зміни рішення на тих самих подіях, результати selection/filter, фактичні й очікувані значення. Це окремі аналізи; автоматичне визначення регресій виконується регресійним сценарієм.

### Перевірка очікування

Дає відповідь, чи відповідає результат правила заданому тестовому прикладу.

**Синтаксис:**

```powershell
.\totenkahn.exe test replay --rule "<RULE_PATH>" --session "<SESSION_DIRECTORY>" --test-case "<TEST_CASE_JSON>"
```

**Приклад:**

```powershell
.\totenkahn.exe test replay --rule "C:\Rules\whoami.yaml" --session "C:\Evidence\whoami-session" --test-case "C:\Tests\whoami-positive.json"
```

Файл має відповідати контракту тестового прикладу. `--test-case` і `--test-context` ручного режиму не є взаємозамінними.

**Що перевірити:** результат очікування — `met`, `not_met` або `insufficient_data`, причину та вибрані докази. Недостатність даних не означає успішного негативного тесту.

### Перегляд зв’язків подій

Допомагає перевірити походження збігів і доступний процесний контекст у збереженій сесії.

**Синтаксис:**

```powershell
.\totenkahn.exe test replay --rule "<RULE_PATH>" --session "<SESSION_DIRECTORY>" --show-correlation
```

**Приклад:**

```powershell
.\totenkahn.exe test replay --rule "C:\Rules\whoami.yaml" --session "C:\Evidence\whoami-session" --show-correlation
```

**Що перевірити:** процесні ідентифікатори, батьківські зв’язки та підстави прив’язки до дії. Відсутній контекст не доповнюється новим збором.

### Рівні деталізації

Дають змогу зберегти звичний рівень підготовчих повідомлень у командах аналізу. У replay їхня користь обмежена, оскільки live-підготовка пропускається.

**Синтаксис:**

```powershell
.\totenkahn.exe test replay --rule "<RULE_PATH>" --session "<SESSION_DIRECTORY>" [-v | -vv]
```

**Приклад:**

```powershell
.\totenkahn.exe test replay --rule "C:\Rules\whoami.yaml" --session "C:\Evidence\whoami-session" -v
```

**Що перевірити:** основний результат правила та його пояснення; рівень деталізації не змінює логіку перевірки й не є додатковою перевіркою доказів.

## 4. Імпорт зовнішніх даних

Перетворює підтримані файли подій на локальний набір доказів із нормалізованими полями та збереженими оригіналами. Набір використовується для пошуку, Sigma-аналізу, розслідувань і hunting.

### Основний імпорт

Створює новий індексований набір із файла або каталогу.

**Синтаксис:**

```powershell
.\totenkahn.exe dump import "<SOURCE>" [--profile "<PROFILE>"] [--name "<DATASET_NAME>" | --output-dir "<NEW_DIRECTORY>"] [OPTIONS]
```

**Приклад:**

```powershell
.\totenkahn.exe dump import "C:\Evidence\events.jsonl" --profile generic-v1 --name workstation-events
```

`--name` зберігає набір у сховищі Totenkahn. `--output-dir` задає новий зовнішній каталог; ці опції не використовуються разом.

**Що перевірити:** `status`, лічильники `counts`, блок `quality`, помилки та шлях `report`. Статус `partial` означає, що збережено лише частину придатних даних.

### Вибір профілю

Визначає, звідки брати час, хост, користувача, командний рядок та інші нормалізовані поля. Правильний профіль дає придатні для пошуку й аналізу значення.

**Синтаксис:**

```powershell
.\totenkahn.exe dump profiles
.\totenkahn.exe dump import "<SOURCE>" --profile "<PROFILE_ID_OR_JSON_PATH>" --name "<DATASET_NAME>"
```

**Приклад власного профілю:**

```powershell
.\totenkahn.exe dump import "C:\Evidence\custom.jsonl" --profile "C:\Profiles\custom-profile.json" --name custom-events
```

Для JSON і табличних джерел профіль задається явно. Для Windows XML/EVTX застосовується відповідний Windows-адаптер.

**Що перевірити:** `quality.field_states`, попередження про відсутні або неоднозначні поля, нормалізований час і хост. Успішне читання файла не гарантує правильного зіставлення полів.

### Попередній перегляд

Дозволяє перевірити профіль на кількох записах до створення набору.

**Синтаксис:**

```powershell
.\totenkahn.exe dump preview "<SOURCE_FILE>" --profile "<PROFILE>" --limit <COUNT>
```

**Приклад:**

```powershell
.\totenkahn.exe dump preview "C:\Evidence\events.jsonl" --profile generic-v1 --limit 3
```

`--limit` приймає `1–20`, типово `5`. Підтримуються XML, JSON, JSONL, NDJSON, CSV і TSV; для EVTX/gzip використовуйте імпорт, потім `dump show`.

**Що перевірити:** `event`, `mapping`, `warnings` і `reason` кожного зразка. Звірте нормалізовані значення з вихідними; перегляд кількох записів не підтверджує якість усього файла.

### Імпорт Windows-подій

Призначений для аналізу збережених журналів Windows без нового live-збору.

**Синтаксис:**

```powershell
.\totenkahn.exe dump import "<XML_OR_EVTX_FILE>" --name "<DATASET_NAME>" [--timeout <SECONDS>]
```

**Приклади:**

```powershell
.\totenkahn.exe dump import "C:\Evidence\Security.xml" --name security-xml
```

```powershell
.\totenkahn.exe dump import "C:\Evidence\Security.evtx" --name security-evtx --timeout 900
```

EVTX-декодування потребує Windows. `--timeout` обмежує декодування одного EVTX-файла; типове значення — `600` секунд.

**Що перевірити:** кількість прийнятих і відхилених записів, помилки декодування, час, канал і провайдер. Після тайм-ауту перевірте статус повноти набору.

### Імпорт експортів Splunk і Kibana Discover

Дає змогу аналізувати вже експортовану телеметрію без прямого підключення застосунку до SIEM.

**Синтаксис:**

```powershell
.\totenkahn.exe dump import "<EXPORT_FILE>" --profile "<SOURCE_PROFILE>" --name "<DATASET_NAME>"
```

**Приклад Splunk:**

```powershell
.\totenkahn.exe dump import "C:\Evidence\splunk.json" --profile splunk-v1 --name splunk-export
```

**Приклад Kibana Discover:**

```powershell
.\totenkahn.exe dump import "C:\Evidence\discover.json" --profile elastic-discover-v1 --name elastic-export
```

Профіль Discover очікує документи з об’єктом `fields`. Повна API-оболонка Elasticsearch `hits.hits` потребує попереднього витягування документів.

**Що перевірити:** коректність часу, хоста й командного рядка; для Discover — походження полів, ідентифікатори документів і попередження про порожні або багатозначні масиви. Імпорт не доводить повноту початкового експорту SIEM.

### Імпорт CSV і TSV

Дозволяє використовувати табличні експорти зі збереженням значень клітинок і явними правилами читання.

**Синтаксис:**

```powershell
.\totenkahn.exe dump import "<TABLE_FILE>" --profile "<PROFILE>" --name "<DATASET_NAME>" [--encoding <ENCODING>] [--delimiter "<CHARACTER>"] [--null-value "<TOKEN>"]
```

**Приклад CSV із крапкою з комою:**

```powershell
.\totenkahn.exe dump import "C:\Evidence\events.csv" --profile generic-v1 --name csv-events --encoding utf-8-sig --delimiter ";" --null-value "NULL"
```

Для TSV типовий роздільник — табуляція. Підтримані кодування: `utf-8-sig`, `utf-16`, `utf-16-le`, `utf-16-be`, `cp1252`.

`--null-value` перетворює лише точний заданий токен на `null`; порожня клітинка без такого перетворення залишається порожнім рядком.

**Що перевірити:** назви колонок, відхилені рядки, `mapping`, початкові значення клітинок і `quality.field_states`. Порожній рядок, `null` та відсутнє поле мають різне значення для аналізу.

### Імпорт gzip

Дає змогу використати стиснений експорт із перевіркою розпакування та збереженням зв’язку з оригіналом.

**Синтаксис:**

```powershell
.\totenkahn.exe dump import "<SUPPORTED_FILE.gz>" --profile "<PROFILE>" --name "<DATASET_NAME>" --max-expanded-mib <LIMIT>
```

**Приклад:**

```powershell
.\totenkahn.exe dump import "C:\Evidence\events.jsonl.gz" --profile generic-v1 --name compressed-events --max-expanded-mib 512
```

Підтримуються gzip-варіанти JSON, JSONL, NDJSON, CSV і TSV. Ліміт розпакування типово становить `1024 MiB` на файл; ZIP і стиснені XML/EVTX цим шляхом не підтримуються.

**Що перевірити:** помилки CRC або перевищення ліміту, статус файла й контрольні суми стисненого та розпакованого вмісту. Пошкоджений gzip не повинен вважатися успішно проіндексованим.

### Імпорт каталогу або збереження поза сховищем

Використовується для групи файлів або розміщення набору на окремому диску. Інженер отримує один набір із походженням записів для кожного джерела.

**Синтаксис:**

```powershell
.\totenkahn.exe dump import "<SOURCE_DIRECTORY>" --profile "<PROFILE>" --output-dir "<NEW_DATASET_DIRECTORY>"
```

**Приклад:**

```powershell
.\totenkahn.exe dump import "C:\Exports\Host01" --profile generic-v1 --output-dir "D:\Cases\Host01-dataset"
```

Каталог обходиться рекурсивно. Вихідний каталог має бути новим і не розташовуватися всередині вхідного; файли з несумісними схемами краще імпортувати окремо з відповідними профілями.

**Що перевірити:** результати кожного файла, непідтримані джерела й загальний `status`. Успішне читання одного файла не означає успішного імпорту всього каталогу.

### Машинний результат імпорту

Призначений для скриптів і збереження структурованого підсумку операції.

**Синтаксис:**

```powershell
.\totenkahn.exe dump import "<SOURCE>" --profile "<PROFILE>" --name "<DATASET_NAME>" --json
```

**Приклад:**

```powershell
.\totenkahn.exe dump import "C:\Evidence\events.jsonl" --profile generic-v1 --name automated-import --json
```

**Що перевірити:** `status`, `counts`, `quality`, `errors` і шляхи артефактів. Код завершення `0` допускає попередження; `3` означає частковий імпорт, `2` — помилку або відсутність придатних подій, `130` — переривання.

## 5. Перегляд і пошук подій

Дозволяє знайти потрібні записи в імпортованих наборах і переглянути їхні повні поля та походження. Використовується для первинного дослідження доказів і перевірки якості даних перед аналізом.

### Перелік наборів

Допомагає знайти збережений набір і перевірити його стан.

**Синтаксис:**

```powershell
.\totenkahn.exe dump list
```

**Приклад:**

```powershell
.\totenkahn.exe dump list --json
```

Команда перелічує набори у внутрішньому сховищі. До зовнішнього набору звертайтеся за його шляхом.

**Що перевірити:** `name`, `path`, `status`, `created_at` і `counts` кожного набору. Загальний `passed` команди не означає, що всі перелічені набори повні.

### Підсумок набору

Дає швидке уявлення про обсяг, часові межі, хости та якість імпортованих даних.

**Синтаксис:**

```powershell
.\totenkahn.exe dump summary "<DATASET_NAME_OR_PATH>"
```

**Приклад:**

```powershell
.\totenkahn.exe dump summary workstation-events
```

**Що перевірити:** `status`, `counts`, `quality.first_time_utc`, `quality.last_time_utc`, `hosts`, `event_types`, `events_with_warnings` і `field_states`. Частотні списки обмежені; вони не замінюють перегляд усіх подій.

### Пошук за хостом, типом або текстом

Звужує набір до записів, які стосуються конкретної інженерної задачі.

**Синтаксис:**

```powershell
.\totenkahn.exe dump search "<DATASET>" [--host "<HOST>"] [--event-type "<TYPE>"] [--text "<TEXT>"]
```

**Приклад за хостом:**

```powershell
.\totenkahn.exe dump search workstation-events --host "HOST01"
```

**Приклад за типом і текстом:**

```powershell
.\totenkahn.exe dump search workstation-events --event-type "process-start" --text "whoami.exe"
```

Фільтри можна поєднувати. Значення типу події беріть із підсумку набору; текст шукається як підрядок raw-запису, а не як Sigma-умова.

**Що перевірити:** `items`, `row_id`, нормалізовані поля, `dataset_status` і `truncated_fields`. Збіг текстового пошуку ще не означає збіг правила.

### Пошук у часовому інтервалі

Дає змогу виділити події навколо тесту або досліджуваного інциденту.

**Синтаксис:**

```powershell
.\totenkahn.exe dump search "<DATASET>" --start "<ISO_TIMESTAMP>" --end "<ISO_TIMESTAMP>"
```

**Приклад:**

```powershell
.\totenkahn.exe dump search workstation-events --start "2026-11-26T14:00:00Z" --end "2026-11-26T15:00:00Z"
```

Часовий пошук можна поєднати з `--host`, `--event-type` і `--text`.

**Що перевірити:** часові значення повернених подій і `coverage`. Записи з невідомим часом виключаються часовими фільтрами, тому порожня відповідь не доводить відсутності активності.

### Посторінковий перегляд

Дозволяє послідовно переглянути великий результат без перевантаження виводу.

**Синтаксис:**

```powershell
.\totenkahn.exe dump search "<DATASET>" --limit <COUNT> [--after <CURSOR>]
```

**Перша сторінка:**

```powershell
.\totenkahn.exe dump search workstation-events --text "whoami.exe" --limit 50 --json
```

**Наступна сторінка, якщо відповідь містить `next_after: 137`:**

```powershell
.\totenkahn.exe dump search workstation-events --text "whoami.exe" --limit 50 --after 137 --json
```

`--limit` приймає `1–500`, типово `50`. Копіюйте фактичне значення `next_after` та зберігайте ті самі фільтри.

**Що перевірити:** `next_after` і `query_limit`. `next_after: null` означає, що наступної сторінки немає; кількість записів поточної сторінки не є загальною кількістю збігів.

### Повний перегляд запису

Використовується для перевірки значень, які скорочені або не показані в результатах пошуку.

**Синтаксис:**

```powershell
.\totenkahn.exe dump show "<DATASET>" --row <ROW_ID>
```

**Приклад:**

```powershell
.\totenkahn.exe dump show workstation-events --row 17
```

`ROW_ID` береться з результату пошуку, а не з Windows Event ID.

**Що перевірити:** `event`, `raw`, `mapping`, `warnings`, `source` і `locator`. Звірте нормалізоване значення з оригіналом і способом його перетворення.

### Перегляд проблем імпорту

Допомагає з’ясувати, чому частина записів не потрапила до набору або не була прочитана коректно.

**Синтаксис:**

```powershell
.\totenkahn.exe dump issues "<DATASET>" [--limit <COUNT>] [--after <CURSOR>]
```

**Приклад:**

```powershell
.\totenkahn.exe dump issues workstation-events --limit 50 --json
```

Для наступної сторінки передайте повернений `next_after` у `--after`.

**Що перевірити:** `reason`, `file_id`, `ordinal`, `locator` і `dataset_status`. Попередження прийнятих подій додатково переглядайте через `summary` та `show`.

### Перевірка цілісності перед використанням

Дозволяє перевірити, чи відповідають збережені файли локальному маніфесту, перш ніж спиратися на них у висновку.

**Синтаксис:**

```powershell
.\totenkahn.exe dump verify "<DATASET>"
```

**Приклад:**

```powershell
.\totenkahn.exe dump verify workstation-events
```

**Що перевірити:** статус перевірки й перелік невідповідностей. У результатах звичайного пошуку `integrity: not_checked_use_dump_verify` означає, що цілісність цією командою не перевірялася. Контрольні суми не є цифровим підписом.

### JSON для подальшої обробки

Дає скриптам структуровані результати пошуку або повного перегляду без розбору термінального оформлення.

**Синтаксис:**

```powershell
.\totenkahn.exe dump search "<DATASET>" [FILTERS] --json
.\totenkahn.exe dump show "<DATASET>" --row <ROW_ID> --json
```

**Приклад:**

```powershell
.\totenkahn.exe dump show workstation-events --row 17 --json
```

**Що перевірити:** `status`, `dataset_status`, `items` і, для пошуку, `next_after`. Навіть із `--json` пошук повертає скорочені записи; для повних полів використовуйте `show`.

## 6. Збережені вибірки доказів

Виділяють потрібні події з імпортованого набору для повторного аналізу або додавання до кейса. Інженер отримує зафіксований склад доказів із фільтрами та посиланнями на вихідні записи.

### Створення вибірки

Використовується, коли потрібно працювати лише з частиною набору, зберігши можливість повторити аналіз на тих самих записах.

**Синтаксис:**

```powershell
.\totenkahn.exe dump select "<DATASET>" [FILTERS] [--name "<SELECTION_NAME>" | --output-dir "<NEW_DIRECTORY>"]
```

**Приклад:**

```powershell
.\totenkahn.exe dump select workstation-events --host "HOST01" --event-type "process-start" --name host01-processes
```

Без фільтрів вибірка містить усі записи. `--name` і `--output-dir` не використовуються разом; каталог результату має бути новим.

**Що перевірити:** статус, збережені `filters`, склад вибірки та `dataset_status`. Порожня вибірка має `needs_verification` і не підтверджує відсутності активності.

### Відбір за джерелом, текстом і часом

Дозволяє обмежити докази конкретним журналом, провайдером, файлом або часовим інтервалом.

**Синтаксис:**

```powershell
.\totenkahn.exe dump select "<DATASET>" [--channel "<CHANNEL>"] [--provider "<PROVIDER>"] [--source "<FILE_NAME_OR_ID>"] [--text "<TEXT>"] [--start "<TIMESTAMP>"] [--end "<TIMESTAMP>"] --name "<SELECTION_NAME>"
```

**Приклад:**

```powershell
.\totenkahn.exe dump select workstation-events --host "HOST01" --text "whoami.exe" --start "2026-11-26T14:00:00Z" --end "2026-11-26T15:00:00Z" --name whoami-window
```

Фільтри поєднуються через AND. Часові межі включні й потребують часового поясу; записи з невідомим часом у такий інтервал не потрапляють.

**Що перевірити:** фактичні часові межі, хост і джерело вибраних записів. Нуль записів може означати надто вузький фільтр або відсутність придатного часу.

### Відбір конкретних записів

Дає змогу зафіксувати вручну переглянуті події, наприклад позитивний і негативний приклади.

**Синтаксис:**

```powershell
.\totenkahn.exe dump select "<DATASET>" --row <ROW_ID> [--row <ROW_ID>] --name "<SELECTION_NAME>"
```

**Приклад:**

```powershell
.\totenkahn.exe dump select workstation-events --row 17 --row 24 --name reviewed-events
```

`ROW_ID` береться з `dump search` або `dump show`; це не Windows Event ID.

**Що перевірити:** що до вибірки потрапили саме переглянуті рядки та їхні ідентифікатори доказів. Якщо додано інші фільтри, вони також обмежують ці рядки.

### Відбір за значенням поля

Використовується для точного зіставлення скалярного поля без пошуку по всьому raw-запису.

**Синтаксис:**

```powershell
.\totenkahn.exe dump select "<DATASET>" --field "/PATH=VALUE" --name "<SELECTION_NAME>"
```

**Приклад:**

```powershell
.\totenkahn.exe dump select workstation-events --field "/user=CORP\analyst" --name analyst-events
```

`--field` можна повторювати. Шлях задається як JSON pointer; для вихідних вкладених полів використовуйте `/fields/...`. Порівнюється текстове представлення скалярного значення.

**Що перевірити:** шлях поля, фактичне значення та збережений фільтр. Масиви не адресуються за індексами; відсутнє поле не слід підміняти порожнім рядком.

### Типізовані фільтри з JSON

Дозволяють явно перевіряти тип значення, наявність поля або входження підрядка. Інженер отримує відтворювані умови відбору в окремому файлі.

**Синтаксис:**

```powershell
.\totenkahn.exe dump select "<DATASET>" --filters "<FILTERS_JSON>" --name "<SELECTION_NAME>"
```

**Приклад вмісту `C:\Filters\whoami.json`:**

```json
{
  "host": "HOST01",
  "fields": [
    {
      "path": "/command_line",
      "op": "contains",
      "value": "whoami"
    }
  ]
}
```

**Приклад запуску:**

```powershell
.\totenkahn.exe dump select workstation-events --filters "C:\Filters\whoami.json" --name whoami-events
```

Підтримуються `equals`, `contains`, `exists` і `text_equals`. Той самий фільтр не можна одночасно задавати через JSON і CLI.

**Що перевірити:** оператори, типи значень та склад вибірки. Для перевірки фізичної наявності вихідного поля використовуйте його шлях у `/fields/...`; нормалізоване поле може існувати зі значенням `null`.

### Перелік і повторне використання вибірок

Допомагає знайти збережений відбір і застосувати його до аналізу без повторного введення фільтрів.

**Синтаксис:**

```powershell
.\totenkahn.exe dump selections
.\totenkahn.exe dump analyze "<DATASET>" --selection "<SELECTION>" --rule "<RULE_PATH>"
```

**Приклад:**

```powershell
.\totenkahn.exe dump selections --json
```

```powershell
.\totenkahn.exe dump analyze workstation-events --selection host01-processes --rule "C:\Rules\whoami.yaml" --mapping "C:\Mappings\process-events.json"
```

Збережену вибірку не можна поєднувати з новими фільтрами аналізу.

**Що перевірити:** відповідність вибірки вихідному набору та зафіксований склад доказів у звіті. Для іншого складу створіть нову вибірку.

## 7. Аналіз Sigma на імпортованих даних

Перевіряє одне або декілька Sigma-правил на імпортованих подіях. Інженер отримує рішення для кожної події, пояснення перевірок і діагностику достатності даних.

### Аналіз одного правила

Використовується для перевірки логіки детекції на збереженій телеметрії без виконання тестових дій.

**Синтаксис:**

```powershell
.\totenkahn.exe dump analyze "<DATASET>" --rule "<RULE_PATH>" [OPTIONS]
```

**Приклад:**

```powershell
.\totenkahn.exe dump analyze workstation-events --rule "C:\Rules\whoami.yaml" --mapping "C:\Mappings\process-events.json"
```

Без вибірки й фільтрів аналізуються всі записи набору.

**Що перевірити:** загальний статус, лічильники рішень і пояснення потрібних подій:

| Рішення | Значення |
|---|---|
| `match` | Даних достатньо, умова правила виконана. |
| `no_match` | Даних достатньо, умова не виконана. |
| `not_applicable` | Відоме джерело події не відповідає правилу. |
| `insufficient_data` | Джерело або потрібні значення не дозволяють зробити підтверджений висновок. |

`passed` означає завершений аналіз, а не обов’язкову наявність збігів.

### Зіставлення полів і джерела

Потрібне, коли імена полів експорту відрізняються від Sigma або джерело неможливо встановити автоматично. Інженер явно визначає, які дані перевіряє правило.

**Синтаксис:**

```powershell
.\totenkahn.exe dump analyze "<DATASET>" --rule "<RULE_PATH>" --mapping "<MAPPING_JSON>"
```

**Приклад mapping для перевіреної вибірки Windows process events:**

```json
{
  "schema_version": 1,
  "id": "reviewed-process-events-v1",
  "logsource": {
    "product": "windows",
    "category": "process_creation"
  },
  "fields": {
    "CommandLine": "/command_line",
    "Image": "/fields/Image"
  }
}
```

**Приклад запуску:**

```powershell
.\totenkahn.exe dump analyze workstation-events --selection host01-processes --rule "C:\Rules\whoami.yaml" --mapping "C:\Mappings\process-events.json"
```

Шляхи мають відповідати фактичній структурі даних. Не призначайте одне джерело змішаним подіям без попереднього відбору.

**Що перевірити:** сумісність `logsource`, шляхи полів, початкові значення та перетворення. Mapping є твердженням інженера про джерело, а не незалежним доказом його походження.

### Перевірка придатності без обчислення збігів

Дозволяє перед основним аналізом з’ясувати, чи достатньо джерел і полів для правила.

**Синтаксис:**

```powershell
.\totenkahn.exe dump analyze "<DATASET>" --rule "<RULE_PATH>" --preflight [--mapping "<MAPPING_JSON>"]
```

**Приклад:**

```powershell
.\totenkahn.exe dump analyze workstation-events --selection host01-processes --rule "C:\Rules\whoami.yaml" --mapping "C:\Mappings\process-events.json" --preflight
```

**Що перевірити:** кількість придатних подій, відсутні поля, невідоме або суперечливе джерело. Preflight не перевіряє виконання умови й не підтверджує `match`.

### Аналіз вибірки або відбір під час запуску

Дозволяє перевіряти лише релевантні докази, зменшуючи кількість сторонніх подій у результаті.

**Синтаксис зі збереженою вибіркою:**

```powershell
.\totenkahn.exe dump analyze "<DATASET>" --selection "<SELECTION>" --rule "<RULE_PATH>" [--mapping "<MAPPING_JSON>"]
```

**Приклад:**

```powershell
.\totenkahn.exe dump analyze workstation-events --selection whoami-window --rule "C:\Rules\whoami.yaml" --mapping "C:\Mappings\process-events.json"
```

**Приклад відбору без попередньої вибірки:**

```powershell
.\totenkahn.exe dump analyze workstation-events --host "HOST01" --row 17 --rule "C:\Rules\whoami.yaml" --mapping "C:\Mappings\process-events.json"
```

Для відбору доступні ті самі фільтри, що й у `dump select`. Без `--selection` склад відбору зберігається разом зі звітом.

**Що перевірити:** фільтри й кількість вибраних подій. Порожній результат або часткове джерело не дають підтвердженого негативного висновку.

### Аналіз каталогу правил

Використовується для перевірки кількох правил на одному наборі доказів.

**Синтаксис:**

```powershell
.\totenkahn.exe dump analyze "<DATASET>" --rules-dir "<RULES_DIRECTORY>" [OPTIONS]
```

**Приклад:**

```powershell
.\totenkahn.exe dump analyze workstation-events --selection host01-processes --rules-dir "C:\Rules\ProcessCreation" --mapping "C:\Mappings\process-events.json"
```

Каталог обходиться рекурсивно. `--rule` і `--rules-dir` не використовуються разом; помилка одного правила не видаляє результати інших.

**Що перевірити:** статус кожного правила, помилки підтримки синтаксису, кількість `insufficient_data` та пояснення збігів. Загальний підсумок не замінює перевірки окремих правил.

### Окремий каталог і машинний результат

Допомагає зберігати незалежні запуски й передавати результати іншим інструментам.

**Синтаксис:**

```powershell
.\totenkahn.exe dump analyze "<DATASET>" --rule "<RULE_PATH>" --output-dir "<NEW_DIRECTORY>" --json
```

**Приклад:**

```powershell
.\totenkahn.exe dump analyze workstation-events --rule "C:\Rules\whoami.yaml" --mapping "C:\Mappings\process-events.json" --output-dir "C:\Reports\whoami-analysis-01" --json
```

**Що перевірити:** шляхи `report` і `html`, точну копію правила, mapping і склад вибірки. У детальних результатах звірте фактичні значення, selection/filter і дерево умови; позначене `provisional` рішення не є підтвердженою детекцією.

## 8. Ведення кейсів

Об’єднує докази, нотатки й історію роботи в окрему справу розслідування. Інженер отримує переносний контекст для хронології, hunting і подальшої перевірки знахідок.

### Створення кейса

Створює окреме місце для матеріалів конкретного дослідження.

**Синтаксис:**

```powershell
.\totenkahn.exe case create --title "<TITLE>" [--description "<DESCRIPTION>"] [--name "<CASE_NAME>" | --output-dir "<NEW_DIRECTORY>"]
```

**Приклад:**

```powershell
.\totenkahn.exe case create --name investigation --title "Перевірка HOST01" --description "Аналіз запусків процесів"
```

Для зовнішнього розташування замініть `--name` на `--output-dir`.

**Що перевірити:** `case_id` і шлях `case`. Новий кейс ще не містить доказів.

### Додавання набору або вибірки

Прикріплює докази до кейса, щоб дослідження не залежало від подальшого переміщення вихідного набору.

**Синтаксис:**

```powershell
.\totenkahn.exe case add "<CASE>" --dataset "<DATASET>" [--selection "<SELECTION>"] [--label "<LABEL>"]
```

**Приклад із вибіркою:**

```powershell
.\totenkahn.exe case add investigation --dataset workstation-events --selection host01-processes --label workstation
```

**Приклад додавання всього іншого набору:**

```powershell
.\totenkahn.exe case add investigation --dataset server-events --label server
```

Мітки мають бути унікальними. Навіть із вибіркою копіюються повні оригінали й індекс набору; вибірка визначає записи для дослідження.

**Що перевірити:** повернений `attachment`, його набір і вибірку, статус джерела та обмеження повноти. Прикріплення часткового набору не робить його повним.

### Перелік і перегляд кейсів

Дає змогу знайти потрібне дослідження та перевірити його поточний склад.

**Синтаксис:**

```powershell
.\totenkahn.exe case list
.\totenkahn.exe case show "<CASE>"
```

**Приклад:**

```powershell
.\totenkahn.exe case list --json
```

```powershell
.\totenkahn.exe case show investigation --json
```

`case list` показує кейси внутрішнього сховища; зовнішній кейс відкривається за шляхом.

**Що перевірити:** назву, стан, вкладення, нотатки та історію. `integrity: metadata_only_use_case_verify` означає, що повна перевірка доказів ще не виконувалася.

### Нотатки до кейса, джерела або події

Зберігають пояснення інженера поруч із відповідними доказами.

**Синтаксис:**

```powershell
.\totenkahn.exe case note "<CASE>" --author "<AUTHOR>" --text "<TEXT>" [--attachment "<LABEL_OR_ID>"] [--row <ROW_ID>] [--tag "<TAG>"]
```

**Нотатка до всього кейса:**

```powershell
.\totenkahn.exe case note investigation --author engineer --text "Перевірити походження запусків whoami" --tag review
```

**Нотатка до конкретної події:**

```powershell
.\totenkahn.exe case note investigation --author engineer --text "Командний рядок відповідає ручній перевірці" --attachment workstation --row 17 --tag reviewed
```

Без `--row` нотатка з `--attachment` стосується джерела. `--tag` можна повторювати; рядок має належати прикріпленій вибірці.

**Що перевірити:** автора, текст, час і посилання на attachment/row/evidence ID. Нотатка є твердженням інженера, а не спостереженою подією; уточнення додаються новими нотатками.

### Перевірка цілісності кейса

Перевіряє матеріали перед аналізом або передаванням іншому інженеру.

**Синтаксис:**

```powershell
.\totenkahn.exe case verify "<CASE>"
```

**Приклад:**

```powershell
.\totenkahn.exe case verify investigation
```

**Що перевірити:** статус, невідповідності й `limitations`. Успішна перевірка цілісності не підтверджує повноту збору або правильність висновків.

### Закриття та повторне відкриття

Фіксує завершення роботи або її поновлення з автором і причиною.

**Синтаксис:**

```powershell
.\totenkahn.exe case status "<CASE>" --set <open|closed> --author "<AUTHOR>" --reason "<REASON>"
```

**Закриття:**

```powershell
.\totenkahn.exe case status investigation --set closed --author engineer --reason "Перегляд доказів завершено"
```

**Повторне відкриття:**

```powershell
.\totenkahn.exe case status investigation --set open --author engineer --reason "Отримано додаткові події"
```

Закритий кейс можна читати, аналізувати й експортувати. Для додавання доказів, нотаток або нової гіпотези його потрібно відкрити.

**Що перевірити:** новий стан і запис історії. Закриття є рішенням інженера, а не автоматичним підтвердженням завершеності розслідування.

### Експорт і перенесення

Створює переносний ZIP із кейсом та прикріпленими доказами.

**Синтаксис:**

```powershell
.\totenkahn.exe case export "<CASE>" --output "<NEW_ZIP_PATH>"
```

**Приклад:**

```powershell
.\totenkahn.exe case export investigation --output "C:\Exports\investigation.zip"
```

Архів має бути новим і розташовуватися поза кейсом. Він містить повні оригінали прикріплених наборів, включно з даними поза вибірками; зовнішні звіти запусків передаються окремо.

**Перевірка після перенесення:**

```powershell
Expand-Archive -LiteralPath "C:\Exports\investigation.zip" -DestinationPath "C:\Received\investigation"
```

```powershell
.\totenkahn.exe case verify "C:\Received\investigation"
```

**Що перевірити:** успішне завершення експорту та результат `case verify` після розпакування. Сам факт існування ZIP не підтверджує завершеність експорту.

## 9. Спільна хронологія

Об’єднує події прикріплених доказів у часову послідовність. Інженер отримує огляд активності з переходами до вихідних записів і нотаток.

### Побудова хронології

Використовується для огляду порядку подій із різних джерел кейса.

**Синтаксис:**

```powershell
.\totenkahn.exe case timeline "<CASE>" [OPTIONS]
```

**Приклад:**

```powershell
.\totenkahn.exe case timeline investigation
```

Відомий час сортується в UTC. Події без придатного часу показуються окремо наприкінці.

**Що перевірити:** `status`, `events`, `unknown_time`, `excluded` і `limitations`. Часовий порядок не доводить причинного зв’язку між діями.

### Відбір за хостом, користувачем або процесом

Допомагає дослідити активність конкретного об’єкта без перегляду всього кейса.

**Синтаксис:**

```powershell
.\totenkahn.exe case timeline "<CASE>" [--host "<HOST>"] [--user "<USER>"] [--process-id "<PID>"]
```

**Приклад:**

```powershell
.\totenkahn.exe case timeline investigation --host "HOST01" --process-id "7536"
```

Усі задані фільтри поєднуються через AND.

**Що перевірити:** хост, PID, користувача й час кожної події. PID може використовуватися повторно, тому сам по собі не є унікальною ідентичністю процесу.

### Обмеження часовим інтервалом

Дозволяє зосередитися на періоді тесту або інциденту.

**Синтаксис:**

```powershell
.\totenkahn.exe case timeline "<CASE>" --start "<TIMESTAMP>" --end "<TIMESTAMP>"
```

**Приклад:**

```powershell
.\totenkahn.exe case timeline investigation --host "HOST01" --start "2026-11-26T14:00:00Z" --end "2026-11-26T15:00:00Z"
```

Межі включні й потребують часового поясу. Події з невідомим часом виключаються.

**Що перевірити:** `filters`, `excluded` і часові значення записів. Порожня хронологія може бути наслідком невідомого часу, а не відсутності подій.

### Збереження окремого звіту

Створює незалежний snapshot хронології для перегляду або подальшої обробки.

**Синтаксис:**

```powershell
.\totenkahn.exe case timeline "<CASE>" --output-dir "<NEW_DIRECTORY>" --json
```

**Приклад:**

```powershell
.\totenkahn.exe case timeline investigation --output-dir "C:\Reports\investigation-timeline-01" --json
```

Каталог має бути новим і розташовуватися поза кейсом. HTML містить сторінки подій; `events.jsonl` — повний машинний результат.

**Що перевірити:** шляхи `report` і `html`, ревізію кейса та походження потрібних подій: attachment, row, source hash і locator. `needs_verification` означає, що потрібно переглянути порожній результат, невідомий час або інші обмеження.

## 10. Threat Hunting

Перевіряє явні гіпотези на доказах, прикріплених до кейса, і показує спостережені сутності. Інженер отримує збіги, незбіги, невизначені рішення та пояснення їхніх причин.

### Створення простої гіпотези

Використовується для перевірки однієї умови без підготовки JSON-файла.

**Синтаксис:**

```powershell
.\totenkahn.exe hunt define "<CASE>" --name "<HUNT_NAME>" --author "<AUTHOR>" --hypothesis "<DESCRIPTION>" --field "<JSON_POINTER>" --op <OPERATOR> --value "<VALUE>"
```

**Приклад:**

```powershell
.\totenkahn.exe hunt define investigation --name whoami-review --author engineer --hypothesis "Перевірити наявність запусків whoami" --field /command_line --op contains --value "whoami" --ignore-case
```

Кейс має бути відкритим. Текст гіпотези пояснює намір; результат визначається заданою умовою. Для нової редакції використовуйте нову назву.

**Що перевірити:** збережені поле, оператор, значення, автор і гіпотеза. `passed` для `define` означає збереження визначення, а не виконання пошуку.

### Типізовані значення та масиви

Дозволяє розрізняти числа, рядки, `null` і boolean, а також явно задавати спосіб перевірки масиву.

**Синтаксис:**

```powershell
.\totenkahn.exe hunt define "<CASE>" --name "<HUNT_NAME>" --author "<AUTHOR>" --hypothesis "<DESCRIPTION>" --field "<PATH>" --op <OPERATOR> --value-json "<JSON_VALUE>" [--values <any|all>]
```

**Приклад пошуку відсутнього командного рядка:**

```powershell
.\totenkahn.exe hunt define investigation --name missing-command-line --author engineer --hypothesis "Знайти записи без командного рядка" --field /command_line --op exists --value-json false
```

**Приклад перевірки поля-масиву:**

```powershell
.\totenkahn.exe hunt define investigation --name tag-review --author engineer --hypothesis "Знайти події з міткою review" --field /fields/tags --op equals --value "review" --values any
```

`--values any` вимагає відповідного елемента, `all` — виконання умови для всіх елементів. `--value` і `--value-json` не використовуються разом.

**Що перевірити:** типи фактичного й очікуваного значень, квантор масиву та причини `unknown`. Рядок `"7"` і число `7` не є тотожними; відсутнє поле не стає звичайним незбігом.

### Складена гіпотеза з JSON

Поєднує кілька умов і явну область застосування. Інженер отримує відтворюване визначення з деревом логічних перевірок.

**Синтаксис:**

```powershell
.\totenkahn.exe hunt define "<CASE>" --name "<HUNT_NAME>" --author "<AUTHOR>" --spec "<SPEC_JSON>"
```

**Приклад визначення:**

```json
{
  "schema_version": 1,
  "hypothesis": "Перевірити запуски whoami на HOST01",
  "scope": {
    "field": "/host",
    "op": "equals",
    "value": "HOST01"
  },
  "condition": {
    "all": [
      {
        "field": "/command_line",
        "op": "contains",
        "value": "whoami",
        "case_sensitive": false
      },
      {
        "not": {
          "field": "/command_line",
          "op": "contains",
          "value": "--excluded"
        }
      }
    ]
  }
}
```

**Приклад запуску визначення:**

```powershell
.\totenkahn.exe hunt define investigation --name whoami-host01 --author engineer --spec "C:\Hunts\whoami-host01.json"
```

`--spec` не поєднується з inline-параметрами умови. Доступні `all`, `any`, `not`; оператори включають `equals`, `contains`, `starts_with`, `ends_with`, `in`, `exists`, `gt`, `gte`, `lt`, `lte`, `cidr`.

**Що перевірити:** `scope`, дерево `condition`, шляхи й типи значень. `NOT UNKNOWN` залишається `UNKNOWN`; невідомі дані не повинні перетворюватися на підтверджений збіг.

### Перелік і перегляд гіпотез

Допомагає перевірити, яке саме визначення буде використано під час пошуку.

**Синтаксис:**

```powershell
.\totenkahn.exe hunt list "<CASE>"
.\totenkahn.exe hunt show "<CASE>" --name "<HUNT_NAME>"
```

**Приклад:**

```powershell
.\totenkahn.exe hunt list investigation
```

```powershell
.\totenkahn.exe hunt show investigation --name whoami-review --json
```

**Що перевірити:** назву, автора, умови, область пошуку та hash визначення. Переконайтеся, що обрана потрібна редакція гіпотези.

### Виконання гіпотези

Перевіряє збережені умови на прикріплених доказах і створює новий звіт.

**Синтаксис:**

```powershell
.\totenkahn.exe hunt run "<CASE>" --name "<HUNT_NAME>" [--output-dir "<NEW_DIRECTORY>"]
```

**Приклад:**

```powershell
.\totenkahn.exe hunt run investigation --name whoami-review --output-dir "C:\Reports\whoami-hunt-01"
```

Пошук працює локально з матеріалами кейса; він не звертається до SIEM/EDR і не запускає дій на хостах.

**Що перевірити:**

| Поле | Що означає |
|---|---|
| `status` | Чи завершено пошук і чи є обмеження. |
| `hypothesis_result` | Чи спостерігалася умова в перевірених доказах. |
| `scope_status` | Чи достатньо даних для зведення сутностей. |
| `counts` | Кількість рішень за подіями. |

Перегляньте `match`, `no_match`, `out_of_scope`, `insufficient_scope` та `insufficient_data`. `observed_in_evidence` не є автоматичним висновком про атаку.

### Звуження області запуску

Дозволяє застосувати ту саму гіпотезу до конкретного хоста, користувача або періоду без зміни визначення.

**Синтаксис:**

```powershell
.\totenkahn.exe hunt run "<CASE>" --name "<HUNT_NAME>" [--host "<HOST>"] [--user "<USER>"] [--start "<TIMESTAMP>"] [--end "<TIMESTAMP>"]
```

**Приклад:**

```powershell
.\totenkahn.exe hunt run investigation --name whoami-review --host "HOST01" --start "2026-11-26T14:00:00Z" --end "2026-11-26T15:00:00Z"
```

Фільтри додаються до області гіпотези через AND. Межі часу включні й потребують часового поясу.

**Що перевірити:** записані runtime-фільтри, `insufficient_scope` і пояснення невідомого часу. На відміну від простого часового пошуку, невідомий час у hunting не має мовчки ставати підтвердженим виключенням.

### Зведення хостів, користувачів і процесів

Показує, серед яких сутностей спостерігалися збіги, і допомагає вибрати напрям подальшого дослідження.

**Синтаксис:**

```powershell
.\totenkahn.exe hunt scope "<REPORT_DIRECTORY>" --by <host|user|process|command_line>
```

**Приклад:**

```powershell
.\totenkahn.exe hunt scope "C:\Reports\whoami-hunt-01" --by host
```

Команда читає збережений результат, а не виконує hunting повторно.

**Що перевірити:** кількість входжень, `unique_evidence_records`, невідомі сутності й `scope_status`. Групування за PID не гарантує унікальності процесів, а кількість хостів зі збігами не дорівнює кількості скомпрометованих машин.

### Перехід від сутності до доказів

Дає змогу побачити конкретні події, з яких сформовано групу.

**Синтаксис:**

```powershell
.\totenkahn.exe hunt scope "<REPORT_DIRECTORY>" --by <DIMENSION> --value "<VALUE>"
```

**Приклад:**

```powershell
.\totenkahn.exe hunt scope "C:\Reports\whoami-hunt-01" --by host --value "HOST01"
```

**Перегляд збігів із невідомим користувачем:**

```powershell
.\totenkahn.exe hunt scope "C:\Reports\whoami-hunt-01" --by user --value-json null
```

Для `process` використовуйте точний JSON-об’єкт групи через `--value-json`.

**Що перевірити:** attachment, row, evidence ID, source hash, locator і посилання на HTML-подію. У поясненні події звірте фактичні значення та гілку умови, яка дала збіг.

### Посторінковий перегляд і JSON

Дозволяє переглянути всі групи або докази, навіть якщо HTML показує лише верхню частину зведення.

**Синтаксис:**

```powershell
.\totenkahn.exe hunt scope "<REPORT_DIRECTORY>" --by <DIMENSION> [--value "<VALUE>"] --limit <COUNT> [--after <CURSOR>] --json
```

**Перша сторінка:**

```powershell
.\totenkahn.exe hunt scope "C:\Reports\whoami-hunt-01" --by host --limit 50 --json
```

**Наступна сторінка, якщо повернуто `next_after: 50`:**

```powershell
.\totenkahn.exe hunt scope "C:\Reports\whoami-hunt-01" --by host --limit 50 --after 50 --json
```

`--limit` приймає `1–500`. Використовуйте повернений курсор: для груп це offset, для записів — result ID.

**Що перевірити:** `next_after`, ознаку скорочення HTML-зведення та повноту переглянутих сторінок. Для всіх рішень, включно з незбігами й невизначеними результатами, використовуйте `events.jsonl` звіту.


## 11. Оформлення знахідок

Зберігає перевірений інженером висновок із конкретними доказами та очікуванням щодо правила. Findings використовуються для формування позитивних і негативних регресійних прикладів.

### Знахідка за переглянутими подіями

Фіксує очікування для явно вибраних рядків вкладення кейса.

**Синтаксис:**

```powershell
.\totenkahn.exe finding add "<CASE>" --name "<NAME>" --title "<TITLE>" --author "<AUTHOR>" --reason "<REASON>" --expect <match|no-match> --attachment "<LABEL_OR_ID>" --row <ROW_ID> [--row <ROW_ID>]
```

**Приклад:**

```powershell
.\totenkahn.exe finding add investigation --name whoami-positive --title "Контрольований запуск whoami" --author engineer --reason "Команду та її походження перевірено" --expect match --attachment workstation --row 17
```

Кейс має бути відкритим. Рядки повинні належати прикріпленим доказам; назва знахідки має бути новою. Для негативного прикладу використовуйте іншу назву, переглянуті негативні події та `--expect no-match`.

**Що перевірити:** `expected_match`, `evidence`, `author`, `reason` та ідентифікатори рядків. Успішне створення знахідки підтверджує збереження очікування, а не його виконання правилом.

### Знахідка з результату hunting

Переносить переглянуті результати hunting у тестові очікування зі збереженням походження.

**Синтаксис:**

```powershell
.\totenkahn.exe finding add "<CASE>" --name "<NAME>" --title "<TITLE>" --author "<AUTHOR>" --reason "<REASON>" --expect <match|no-match> --hunt-report "<REPORT_DIRECTORY>" --result <RESULT_ID> [--result <RESULT_ID>]
```

**Приклад після перевірки результату 1:**

```powershell
.\totenkahn.exe finding add investigation --name hunt-whoami-positive --title "Переглянутий результат hunting" --author engineer --reason "Докази результату 1 перевірено вручну" --expect match --hunt-report "C:\Reports\whoami-hunt-01" --result 1
```

ID результату береться зі звіту hunting. Не змішуйте `--result` із `--row` або `--hunt-report` із `--attachment`.

**Що перевірити:** `origin`, посилання на докази та задане очікування. Збіг hunting сам по собі не є підтвердженням атаки або правильності майбутнього Sigma-правила.

### Перелік і перегляд знахідок

Допомагає перевірити очікування перед експортом у CI.

**Синтаксис:**

```powershell
.\totenkahn.exe finding list "<CASE>"
.\totenkahn.exe finding show "<CASE>" --name "<NAME>"
```

**Приклад:**

```powershell
.\totenkahn.exe finding list investigation
.\totenkahn.exe finding show investigation --name whoami-positive --json
```

**Що перевірити:** авторство, обґрунтування, очікування та кожне посилання на подію. Для переглянутої редакції створіть нову знахідку; не змінюйте її службові дані вручну.

## 12. Регресійна перевірка правил

Порівнює baseline і candidate на однакових тестових прикладах. Інженер бачить, які очікування нове правило покращило, порушило або залишило без змін.

### Порівняння двох правил

Використовується перед прийняттям зміни правила.

**Синтаксис:**

```powershell
.\totenkahn.exe --regression-suite "<SUITE_JSON>" --baseline-rule "<BASELINE_YAML>" --candidate-rule "<CANDIDATE_YAML>" --output-dir "<NEW_DIRECTORY>"
```

**Приклад:**

```powershell
.\totenkahn.exe --regression-suite "C:\Tests\whoami-suite.json" --baseline-rule "C:\Rules\whoami-v1.yaml" --candidate-rule "C:\Rules\whoami-v2.yaml" --output-dir "C:\Reports\whoami-regression-01"
```

Набір має відповідати контракту regression suite. Для сесій він посилається на файли тестових прикладів і каталоги сесій; для reviewed findings використовуйте експорт із пункту 13.

**Що перевірити:** результат baseline і candidate для кожного прикладу, а також `comparison`: `improved`, `regressed`, `unchanged_met`, `unchanged_not_met`, `insufficient_data`. Незмінний результат може залишатися неправильним.

### Повторне порівняння після правки

Дозволяє перевірити виправлення на незмінних доказах, зберігаючи попередні звіти.

**Синтаксис:**

```powershell
.\totenkahn.exe --regression-suite "<SAME_SUITE>" --baseline-rule "<SAME_BASELINE>" --candidate-rule "<UPDATED_CANDIDATE>" --output-dir "<NEW_DIRECTORY>"
```

**Приклад:**

```powershell
.\totenkahn.exe --regression-suite "C:\Tests\whoami-suite.json" --baseline-rule "C:\Rules\whoami-v1.yaml" --candidate-rule "C:\Rules\whoami-v3.yaml" --output-dir "C:\Reports\whoami-regression-02"
```

**Що перевірити:** точні копії правил, hashes, незмінність доказів і причини зміни рішень. Різницю після зміни mapping або рушія не можна безумовно приписувати лише правилу.

## 13. Перетворення findings на регресійний комплект

Експортує переглянуті знахідки разом із доказами, правилами та конфігурацією CI. Інженер отримує переносний набір, який можна повторно перевіряти без початкового кейса.

### Експорт вибраних знахідок

Формує позитивні й негативні приклади для baseline/candidate перевірки.

**Синтаксис:**

```powershell
.\totenkahn.exe finding export "<CASE>" --name "<FINDING>" [--name "<FINDING>"] --baseline "<RULE>" --candidate "<RULE>" [--mapping "<MAPPING_JSON>"] --output-dir "<NEW_DIRECTORY>"
```

**Приклад після створення обох знахідок:**

```powershell
.\totenkahn.exe finding export investigation --name whoami-positive --name whoami-negative --baseline "C:\Rules\whoami-v1.yaml" --candidate "C:\Rules\whoami-v2.yaml" --mapping "C:\Mappings\process-events.json" --output-dir "C:\Bundles\whoami-01"
```

Експорт містить snapshot кейса, suite, mapping, конфігурацію, правила й evidence lock. Він переносить повні оригінали вкладень, включно з даними поза вибраними findings. Ліміт набору — 500 посилань на події сумарно.

**Що перевірити:** склад findings, очікування, статус експорту та відсутність ознаки незавершеного експорту. Конфліктні очікування щодо одного доказу потрібно переглянути, а не обходити.

### Перевірка й запуск комплекту

Перевіряє цілісність перенесених доказів, а потім оцінює правила.

**Синтаксис:**

```powershell
.\totenkahn.exe finding verify-bundle "<BUNDLE_DIRECTORY>"
.\totenkahn.exe ci --config "<BUNDLE_DIRECTORY>\pipeline.json" --output-dir "<NEW_DIRECTORY>"
```

**Приклад:**

```powershell
.\totenkahn.exe finding verify-bundle "C:\Bundles\whoami-01"
.\totenkahn.exe ci --config "C:\Bundles\whoami-01\pipeline.json" --output-dir "C:\Reports\whoami-ci-01"
```

Baseline і candidate можна змінювати для наступних запусків; кожен запуск зберігає їх точні копії. Для зміни доказів, mapping або очікувань створіть новий переглянутий експорт.

**Що перевірити:** `scope` і `limitations` перевірки bundle, а потім CI gates. `verify-bundle` підтверджує цілісність, а не правильність очікувань.

## 14. Автоматизовані перевірки Detection CI

Запускає регресійні jobs із визначеними критеріями проходження. Інженер або CI-система отримує підсумок, детальні звіти й код завершення.

### Запуск pipeline

Використовується для однакової перевірки змін правил локально та в автоматизації.

**Синтаксис:**

```powershell
.\totenkahn.exe ci --config "<PIPELINE_JSON>" --output-dir "<NEW_DIRECTORY>"
```

**Приклад:**

```powershell
.\totenkahn.exe ci --config "C:\Bundles\whoami-01\pipeline.json" --output-dir "C:\Reports\ci-run-01"
```

Відносні шляхи jobs обчислюються від файла конфігурації. Кожен запуск потребує нового каталогу результатів.

**Що перевірити:** статус кожного job, `counts`, `violations` та підсумок. Код `0` означає виконання gates, `1` — їх порушення, `2` — помилку входів/виконання, `130` — переривання.

### Налаштування критеріїв і кількох jobs

Дозволяє визначити допустимі результати для одного або кількох наборів.

**Приклад конфігурації:**

```json
{
  "schema_version": 1,
  "gates": {
    "max_regressed": 0,
    "max_not_met": 0,
    "max_insufficient": 0,
    "min_cases": 2
  },
  "jobs": [
    {
      "id": "whoami",
      "suite": "whoami/suite.json",
      "baseline": "whoami/baseline.yaml",
      "candidate": "whoami/candidate.yaml"
    }
  ]
}
```

Для іншого набору додайте job з унікальним `id` та власними шляхами.

**Синтаксис і приклад запуску конфігурації:**

```powershell
.\totenkahn.exe ci --config "<PIPELINE_JSON>" --output-dir "<NEW_DIRECTORY>"
.\totenkahn.exe ci --config "C:\Bundles\pipeline.json" --output-dir "C:\Reports\multi-ci-01"
```

**Що перевірити:** пороги `max_regressed`, `max_not_met`, `max_insufficient`, `min_cases` і фактичні лічильники. Послаблення порогів не змінює сирі failure/skipped у JUnit; зовнішній publisher може бути суворішим за exit code.

### Використання результату в автоматизації

Дозволяє наступному кроку pipeline приймати рішення за кодом завершення.

**Приклад PowerShell:**

```powershell
.\totenkahn.exe ci --config "C:\Bundles\whoami-01\pipeline.json" --output-dir "C:\Reports\ci-run-02"
$ciExit = $LASTEXITCODE
exit $ciExit
```

**Що перевірити:** `report.json`, `report.html`, `junit.xml` та докладний regression report. CI перевіряє правила, але не розгортає їх автоматично в SIEM.

## 15. Нормалізація даних

Перетворює підтримані формати до спільних полів, зберігаючи вихідні значення та відомості про перетворення. Інженер отримує узгоджені поля для пошуку й аналізу.

### Вибір і перевірка профілю

Дозволяє переконатися, що час, хост та інші поля читаються з правильних місць.

**Синтаксис:**

```powershell
.\totenkahn.exe dump profiles
.\totenkahn.exe dump preview "<SOURCE>" --profile "<PROFILE>" --limit <COUNT>
```

**Приклад:**

```powershell
.\totenkahn.exe dump preview "C:\Evidence\discover.json" --profile elastic-discover-v1 --limit 3
```

**Що перевірити:** `event`, `mapping`, `original_value`, `conversion`, `state`, `warnings`. Неоднозначні масиви не повинні мовчки скорочуватися до першого значення; час без пояса не повинен отримувати вигаданий пояс.

### Власний профіль вкладених полів

Потрібний для сумісного JSON-експорту з іншими назвами або структурою полів.

**Приклад профілю:**

```json
{
  "schema_version": 1,
  "id": "custom-process-v1",
  "time_format": "iso8601",
  "mappings": {
    "timestamp": ["event", "created"],
    "host": ["device", "name"],
    "event_id": ["event", "code"],
    "command_line": ["process", "command_line"]
  }
}
```

**Синтаксис:**

```powershell
.\totenkahn.exe dump import "<SOURCE>" --profile "<PROFILE_JSON>" --name "<NEW_DATASET>"
```

**Приклад:**

```powershell
.\totenkahn.exe dump import "C:\Evidence\custom.jsonl" --profile "C:\Profiles\custom-process.json" --name custom-processes
```

Елементи шляху профілю — буквальні ключі: ключ із крапкою задається одним елементом. Профіль імпорту відрізняється від Sigma mapping із JSON pointers.

**Що перевірити:** snapshot профілю в manifest, його hash, поля перших записів і `quality.field_states`. Для застосування виправленого профілю створіть новий набір; попередній автоматично не перенормалізовується.

## 16. Контроль якості та достатності даних

Відокремлює відсутні, пошкоджені або неоднозначні докази від коректного незбігу. Інженер отримує причини, через які результат потребує перевірки.

### Якість імпорту

Допомагає визначити, які джерела й поля придатні для подальшого аналізу.

**Синтаксис:**

```powershell
.\totenkahn.exe dump summary "<DATASET>" --json
.\totenkahn.exe dump issues "<DATASET>" --json
.\totenkahn.exe dump show "<DATASET>" --row <ROW_ID> --json
```

**Приклад:**

```powershell
.\totenkahn.exe dump summary workstation-events --json
.\totenkahn.exe dump issues workstation-events --limit 50 --json
.\totenkahn.exe dump show workstation-events --row 17 --json
```

**Що перевірити:** `counts`, `quality.warning_counts`, `quality.field_states`, причини відхилення й попередження запису. Відсутність, порожній рядок і явний `null` — різні стани.

### Достатність для конкретного правила

Показує, чи дозволяють саме потрібні правилу поля отримати підтверджене рішення.

**Синтаксис:**

```powershell
.\totenkahn.exe dump analyze "<DATASET>" --rule "<RULE>" --mapping "<MAPPING>" --preflight
```

**Приклад:**

```powershell
.\totenkahn.exe dump analyze workstation-events --rule "C:\Rules\whoami.yaml" --mapping "C:\Mappings\process-events.json" --preflight
```

**Що перевірити:** придатність джерела, відсутні поля й непридатні значення. Після повного аналізу окремо перевірте `insufficient_data` і provisional-результати; їх не можна трактувати як підтверджений негативний тест.

## 17. Походження та цілісність доказів

Зберігає зв’язок результату з оригінальним файлом і конкретним записом. Інженер може перевірити локальні контрольні суми та простежити походження висновку.

### Перевірка різних об’єктів

Використовується перед аналізом або після перенесення матеріалів.

**Синтаксис:**

```powershell
.\totenkahn.exe dump verify "<DATASET>"
.\totenkahn.exe case verify "<CASE>"
.\totenkahn.exe finding verify-bundle "<BUNDLE>"
```

**Приклад:**

```powershell
.\totenkahn.exe dump verify workstation-events
.\totenkahn.exe case verify investigation
.\totenkahn.exe finding verify-bundle "C:\Bundles\whoami-01"
```

**Що перевірити:** статус, змінені/відсутні файли й обмеження. SHA-256 перевіряє відповідність локальному manifest, але не є цифровим підписом або автентифікованим chain of custody.

### Простеження окремої події

Допомагає перевірити, з якого файла й запису отримано значення, що вплинуло на висновок.

**Синтаксис:**

```powershell
.\totenkahn.exe dump show "<DATASET>" --row <ROW_ID> --json
```

**Приклад:**

```powershell
.\totenkahn.exe dump show workstation-events --row 17 --json
```

**Що перевірити:** `source`, `file_id`, `ordinal`, `locator`, `raw`, `mapping` та hash оригіналу. Однаковий вміст різних записів не доводить тотожності реальної дії.

## 18. Пояснення рішення Sigma

Показує, які значення, блоки та логічні умови спричинили результат правила. Інженер може знайти причину збігу, незбігу або недостатності даних.

### Аналіз конкретного запису

Зменшує звіт до події, рішення для якої потрібно пояснити.

**Синтаксис:**

```powershell
.\totenkahn.exe dump analyze "<DATASET>" --row <ROW_ID> --rule "<RULE>" [--mapping "<MAPPING>"] --output-dir "<NEW_DIRECTORY>"
```

**Приклад:**

```powershell
.\totenkahn.exe dump analyze workstation-events --row 17 --rule "C:\Rules\whoami.yaml" --mapping "C:\Mappings\process-events.json" --output-dir "C:\Reports\row17-explanation"
```

Окремої команди `explain` немає: пояснення входить до результату аналізу.

**Що перевірити:** actual/expected, modifiers, наявність поля, результати selection/filter і дерево condition. Якщо selection і filter істинні, умова `selection and not filter` має дати незбіг.

### Пояснення зміни між версіями

Допомагає встановити, яка саме правка спричинила регресію або покращення.

**Синтаксис:**

```powershell
.\totenkahn.exe --regression-suite "<SUITE>" --baseline-rule "<BASELINE>" --candidate-rule "<CANDIDATE>" --output-dir "<NEW_DIRECTORY>"
```

**Приклад:**

```powershell
.\totenkahn.exe --regression-suite "C:\Tests\whoami-suite.json" --baseline-rule "C:\Rules\whoami-v1.yaml" --candidate-rule "C:\Rules\whoami-v2.yaml" --output-dir "C:\Reports\explained-regression"
```

**Що перевірити:** пояснення обох правил на тому самому доказі, змінені перевірки та `comparison`. Спочатку відокремте зміну умови від зміни достатності даних.

## 19. Кореляція процесів і контекст тесту

Показує доступні зв’язки подій із процесами та тестовим запуском. Інженер може відокремити докази потрібної дії від сторонніх збігів.

### Деталізація збереженого автоматичного запуску

Використовується для перегляду кореляції без повторного виконання тесту.

**Синтаксис:**

```powershell
.\totenkahn.exe test replay --rule "<RULE>" --session "<SESSION>" --show-correlation
```

**Приклад:**

```powershell
.\totenkahn.exe test replay --rule "C:\Rules\whoami.yaml" --session "C:\Evidence\whoami-session" --show-correlation
```

Подробиці залежать від збережених процесних ідентифікаторів і метаданих запуску. Для ручних сесій окремий термінальний перегляд кореляції автоматичних запусків не виводиться.

**Що перевірити:** GUID/PID, батьківські зв’язки, часові межі й підставу зв’язку з тестом. PID або близькість у часі без додаткових доказів не доводять причинності.

### Перегляд графа у звіті

Допомагає візуально дослідити контекст збігу та деталі вузлів.

**Синтаксис і приклад створення звіту:**

```powershell
.\totenkahn.exe test replay --rule "<RULE>" --session "<SESSION>"
.\totenkahn.exe test replay --rule "C:\Rules\whoami.yaml" --session "C:\Evidence\whoami-session"
```

Відкрийте сформований HTML і скористайтеся переглядом графа; окремої CLI-команди побудови графа немає.

**Що перевірити:** позначення підтверджених зв’язків, групування непов’язаних подій та деталі кожного вузла. Граф не додає доказів, відсутніх у сесії.

## 20. Звіти та візуальне представлення

Надає результати у читабельному та машинному вигляді. Інженер обирає HTML для дослідження, JSON/JSONL для обробки та JUnit для CI.

### Звіт аналізу або hunting

Створює детальні сторінки подій із поясненнями й походженням.

**Синтаксис:**

```powershell
.\totenkahn.exe dump analyze "<DATASET>" --rule "<RULE>" --output-dir "<NEW_DIRECTORY>" --json
.\totenkahn.exe hunt run "<CASE>" --name "<HUNT>" --output-dir "<NEW_DIRECTORY>" --json
```

**Приклад:**

```powershell
.\totenkahn.exe hunt run investigation --name whoami-review --output-dir "C:\Reports\hunt-review-02" --json
```

CLI JSON є підсумком із посиланнями, а не обов’язково повним вмістом усіх подій. Деталі зберігаються у файлах звіту.

**Що перевірити:** `report`, `html`, `status`, сторінки подій і повні JSONL. Не обмежуйте висновок лише першою HTML-сторінкою або top-групами.

### Звіти CI

Дозволяють одночасно досліджувати причини результату й передавати його тестовій системі.

**Синтаксис:**

```powershell
.\totenkahn.exe ci --config "<PIPELINE>" --output-dir "<NEW_DIRECTORY>"
```

**Приклад:**

```powershell
.\totenkahn.exe ci --config "C:\Bundles\whoami-01\pipeline.json" --output-dir "C:\Reports\ci-report-03"
```

**Що перевірити:** узгодженість `report.json`, `report.html`, `junit.xml` та докладних причин. Skipped через недостатні дані не означає успішну перевірку.

## 21. Відновлення наборів доказів

Створює новий індекс із перевірених збережених оригіналів після переривання або проблем із набором. Початковий набір залишається незмінним.

### Відновлення й перевірка

Використовується, коли потрібно повторно отримати доступ до вже збережених доказів.

**Синтаксис:**

```powershell
.\totenkahn.exe dump recover "<DATASET>" --output-dir "<NEW_DIRECTORY>" [--timeout <SECONDS>] [--json]
.\totenkahn.exe dump verify "<NEW_DIRECTORY>"
```

**Приклад:**

```powershell
.\totenkahn.exe dump recover "C:\Evidence\interrupted-dataset" --output-dir "C:\Evidence\recovered-dataset" --json
.\totenkahn.exe dump verify "C:\Evidence\recovered-dataset"
```

Відновлення індексує збережені оригінали з початку, а не продовжує стару транзакцію. Файли, до яких початковий імпорт ще не дійшов, автоматично не відновлюються.

**Що перевірити:** `status`, `counts`, `recovery`, `limitations`, причини відхилення оригіналів і зв’язок із попереднім dataset. Успішне переіндексування не відновлює невідомі пропуски збору.

### Відновлення Windows EVTX

Дозволяє надати більше часу декодуванню великого збереженого журналу.

**Синтаксис:**

```powershell
.\totenkahn.exe dump recover "<EVTX_DATASET>" --output-dir "<NEW_DIRECTORY>" --timeout <SECONDS>
```

**Приклад:**

```powershell
.\totenkahn.exe dump recover "C:\Evidence\security-interrupted" --output-dir "C:\Evidence\security-recovered" --timeout 900
```

Потрібні Windows, робочий декодер і додаткове місце для копій. Підтримується відновлення за збереженим профілем і reader options у межах реалізованого контракту.

**Що перевірити:** тайм-аут, помилки декодера, hashes оригіналів і повноту нового набору. Збільшення часу не виправляє змінений або недокопійований оригінал.

## 22. Керування залежностями

Перевіряє та готує базові компоненти й ресурси вибраного Atomic-тесту. Інженер отримує окремий стан кожного компонента та причину неготовності.

### Стан і план

Допомагає побачити необхідні компоненти до встановлення.

**Синтаксис:**

```powershell
.\totenkahn.exe dependencies status [--json]
.\totenkahn.exe dependencies plan [--offline] [--cache "<CACHE>"] [--atomic-dir "<ATOMIC_DIRECTORY>"]
```

**Приклад:**

```powershell
.\totenkahn.exe dependencies status --json
.\totenkahn.exe dependencies plan
```

**Що перевірити:** сумісність, походження, версії, фактичні шляхи та блокування. Наявність файла не обов’язково означає придатність компонента.

### Підготовка базових компонентів

Встановлює потрібні базові залежності після перегляду плану й згоди.

**Синтаксис:**

```powershell
.\totenkahn.exe dependencies prepare [--yes] [--offline] [--cache "<CACHE>"] [--atomic-dir "<ATOMIC_DIRECTORY>"]
```

**Приклад локального кешу:**

```powershell
.\totenkahn.exe dependencies prepare --offline --cache "C:\Packages\TotenkahnCache"
```

Для заздалегідь погодженої автоматизації використовуйте `--yes`. `--atomic-dir` задає власне існуюче розташування Atomic.

**Що перевірити:** статус кожного компонента й повторні перевірки після встановлення. Готові базові модулі не підтверджують готовність конкретного тесту.

### Підготовка ресурсів вибраного тесту

Завантажує або використовує перевірені файли лише потрібного сценарію без виконання Atomic.

**Синтаксис:**

```powershell
.\totenkahn.exe dependencies plan-test --technique <ID> <NUMBER> [--input "NAME=VALUE"]
.\totenkahn.exe dependencies prepare-test --technique <ID> <NUMBER> [--input "NAME=VALUE"] [--yes] [--offline]
```

**Приклад:**

```powershell
.\totenkahn.exe dependencies plan-test --technique T1033 8 --input "whoami_args=/all"
.\totenkahn.exe dependencies prepare-test --technique T1033 8 --input "whoami_args=/all"
```

Додаткові перевірені ресурси можна вказати повторюваними `--asset-file` і `--asset-technique`. Параметри мають відповідати майбутньому запуску.

**Що перевірити:** склад файлів, hashes, недоступні ресурси та підсумок підготовки. `plan-test` може отримувати визначення техніки; для заборони завантажень додайте `--offline`. Підготовка файлів не виконує код передумов тесту.

## 23. Керування готовністю телеметрії

Перевіряє налаштування підтриманих Windows-джерел відповідно до правила. Інженер отримує план потрібних змін і можливість відновити підтверджені власні зміни платформи.

### План і перевірка

Виявляє проблеми конфігурації до live-тесту без внесення змін.

**Синтаксис:**

```powershell
.\totenkahn.exe telemetry plan --rule "<RULE>"
.\totenkahn.exe telemetry check --rule "<RULE>"
```

**Приклад:**

```powershell
.\totenkahn.exe telemetry plan --rule "C:\Rules\whoami.yaml"
.\totenkahn.exe telemetry check --rule "C:\Rules\whoami.yaml" --json
```

**Що перевірити:** вимоги джерела, фактичний стан, запропоновані дії та причину блокування. Готова конфігурація не підтверджує надходження подій.

### Підготовка телеметрії

Застосовує підтримані зміни після перегляду та згоди. Для змін системної конфігурації потрібні відповідні права.

**Синтаксис:**

```powershell
.\totenkahn.exe telemetry prepare --rule "<RULE>" [--dry-run] [--yes] [--sysmon-archive "<ZIP>"] [--accept-sysmon-eula]
```

**Приклад:**

```powershell
.\totenkahn.exe telemetry prepare --rule "C:\Rules\whoami.yaml" --dry-run
.\totenkahn.exe telemetry prepare --rule "C:\Rules\whoami.yaml"
.\totenkahn.exe telemetry check --rule "C:\Rules\whoami.yaml"
```

Локальний офіційний Sysmon ZIP задається через `--sysmon-archive`; ліцензія приймається через `--accept-sysmon-eula`. Наявна чужа конфігурація не повинна мовчки перезаписуватися.

**Що перевірити:** показані зміни, результат їх застосування та повторну перевірку. Непідтримане джерело не слід вважати готовим.

### Відновлення власних змін

Повертає підтверджені налаштування, які змінювала платформа й які після цього не були змінені сторонніми процесами.

**Синтаксис:**

```powershell
.\totenkahn.exe telemetry restore --dry-run
.\totenkahn.exe telemetry restore [--yes] [--json]
```

**Приклад:**

```powershell
.\totenkahn.exe telemetry restore --dry-run
.\totenkahn.exe telemetry restore
```

**Що перевірити:** відновлені, пропущені й заблоковані операції та їхні причини. Не видаляйте журнал змін до завершення відновлення; це не універсальний відкат усіх змін хоста.

## 24. Кероване видалення залежностей

Видаляє підтверджені власні незмінені компоненти Totenkahn. Інженер отримує перелік видаленого та збережених залишків.

### Попередній перегляд і видалення

Дозволяє перевірити вплив операції до підтвердження.

**Синтаксис:**

```powershell
.\totenkahn.exe dependencies remove --dry-run
.\totenkahn.exe dependencies remove [--yes] [--json]
```

**Приклад:**

```powershell
.\totenkahn.exe dependencies remove --dry-run
.\totenkahn.exe dependencies remove
```

Для заздалегідь погодженої автоматизації доступне `--yes --json`. Сторонні компоненти, змінені файли, докази, звіти, кеш і журнали не видаляються безумовно.

**Що перевірити:** перелік операцій, походження компонентів і причини пропуску. Успішна команда не означає видалення portable-каталогу або відновлення телеметрії.

### Послідовність виведення з експлуатації

Допомагає завершити роботу, зберігши докази та відновивши власні системні зміни до видалення компонентів.

**Синтаксис і приклад послідовності:**

```powershell
.\totenkahn.exe telemetry restore --dry-run
.\totenkahn.exe telemetry restore
.\totenkahn.exe dependencies remove --dry-run
.\totenkahn.exe dependencies remove
```

Після перевірки результатів закрийте процес і окремо приберіть portable-каталог, якщо він більше не потрібен. Збережіть необхідні докази та журнали.

**Що перевірити:** залишки обох операцій і завершеність відновлення. Автоматичного безумовного видалення всіх даних однією командою немає.

## 25. Діагностика й самоперевірки

Перевіряє готовність середовища та працездатність основних сценаріїв. Інженер отримує діагностику без необхідності трактувати її як підтвердження всіх реальних джерел.

### Діагностика вибраного режиму

Допомагає зрозуміти, чи придатне середовище для потрібного сценарію.

**Синтаксис:**

```powershell
.\totenkahn.exe doctor --mode <auto|manual|replay|regression> [--json]
```

**Приклад:**

```powershell
.\totenkahn.exe doctor --mode replay --json
```

**Що перевірити:** `environment`, `dependencies`, загальний статус і причини проблем. Неготовий Atomic не повинен автоматично означати недоступність replay.

### Автономна перевірка п’яти етапів

Перевіряє імпорт, Sigma, кейси/хронологію, hunting і findings/CI на синтетичних даних.

**Синтаксис:**

```powershell
.\totenkahn.exe self-test offline [--output-dir "<NEW_DIRECTORY>"] [--json]
```

**Приклад:**

```powershell
.\totenkahn.exe self-test offline --output-dir "C:\Reports\offline-check-01"
```

Сценарій не потребує SIEM, Atomic або live-збору.

**Що перевірити:** `index.html`, статус кожного етапу, очікуваний і фактичний результат. Навмисний failed/insufficient контроль може означати успішну самоперевірку, якщо саме такий результат очікувався.

### Вибрані етапи самоперевірки

Дозволяє перевірити потрібну частину після локальної зміни.

**Синтаксис:**

```powershell
.\totenkahn.exe self-test offline --stage <1..5> [--stage <1..5>] --output-dir "<NEW_DIRECTORY>"
```

**Приклад:**

```powershell
.\totenkahn.exe self-test offline --stage 3 --stage 4 --output-dir "C:\Reports\case-hunt-check-01"
```

**Що перевірити:** виконані етапи та `not_requested` для інших. Успіх вибраних етапів не означає проходження всіх п’яти.

### Операційна перевірка

Перевіряє роботу на синтетичному обсязі, сторінковий перегляд, переривання та відновлення доказів.

**Синтаксис:**

```powershell
.\totenkahn.exe self-test operations --events <COUNT> [--max-peak-mib <MIB>] --output-dir "<NEW_DIRECTORY>"
```

**Приклад:**

```powershell
.\totenkahn.exe self-test operations --events 1000 --max-peak-mib 256 --output-dir "C:\Reports\operations-01"
```

Діапазон подій — 1000–1000000, типово 5000. Бюджет пам’яті типово 256 MiB стосується вимірюваних Python allocations, а не загальної RSS процесу; звіти можуть займати значний обсяг диска.

**Що перевірити:** результати операцій, час, пік виміряної пам’яті, відсутність пропусків сторінок і результат відновлення. Це не тест live/Atomic або приймання реального EDR-експорту.

## 26. Керування збереженими звітами

Показує стандартний каталог звітів і відкриває його у Windows. Інженер може знайти результати попередніх операцій без ручного пошуку службового каталогу.

### Отримання розташування

Дає шлях до стандартного сховища й перевіряє, чи воно існує.

**Синтаксис:**

```powershell
.\totenkahn.exe reports [--json]
```

**Приклад:**

```powershell
.\totenkahn.exe reports --json
```

**Що перевірити:** `reports_directory` і `exists`. Команда не виконує пошук усіх зовнішніх звітів і не перевіряє їхню цілісність.

### Відкриття каталогу

Дозволяє перейти до результатів через файловий менеджер Windows.

**Синтаксис і приклад:**

```powershell
.\totenkahn.exe reports --open
```

Потрібні Windows та наявний каталог. Після відкриття виберіть HTML потрібного запуску.

**Що перевірити:** дату, ідентифікатор запуску, правило, джерело й статус усередині звіту. Наявність файла не підтверджує завершеність операції.

### Звіти поза стандартним каталогом

Потрібне для результатів, збережених через `--output-dir`, або в каталозі, заданому конфігурацією сесійного аналізу.

**Синтаксис створення окремого звіту:**

```powershell
.\totenkahn.exe dump analyze "<DATASET>" --rule "<RULE>" --output-dir "<NEW_DIRECTORY>" --json
```

**Приклад:**

```powershell
.\totenkahn.exe dump analyze workstation-events --rule "C:\Rules\whoami.yaml" --mapping "C:\Mappings\process-events.json" --output-dir "D:\Reports\whoami-01" --json
```

Відкрийте повернений шлях `html` або `report` безпосередньо. `reports --open` відкриває тільки стандартний каталог і не реєструє всі зовнішні результати.

**Що перевірити:** фактичні шляхи артефактів, контекст запуску й наявність пов’язаних файлів. Для незалежної повторної перевірки зберігайте також відповідні докази; сам HTML їх не замінює.

## 27. CI/CD: перевірка версій правил

CI автоматично перевіряє зміни до їх приймання. У Totenkahn окремо перевіряються вихідний код платформи та результати правил на зафіксованих доказах. CD доставляє перевірену збірку на сервер, але активує її лише після окремої згоди оператора.

Ланцюжок: **Git-коміти → перевірка очікувань → живе приймання → Windows-пакет → перевірка доставки → активація → можливий rollback**. Зелений source CI не означає, що створено `.exe`, а успішна доставка не означає готовність усіх live-сценаріїв.

### Перевірка правил із двох Git-комітів

Порівнює baseline та candidate за повними SHA комітів. Код перевірки, контракт і очікування беруться з переглянутої baseline-версії; зміни очікувань у candidate не можуть приховати регресію. Потрібні Git і локальна копія репозиторію з обома комітами.

**Синтаксис:**

```powershell
.\totenkahn.exe ci revisions --repo "<REPOSITORY>" --baseline <FULL_BASELINE_SHA> --candidate <FULL_CANDIDATE_SHA> --output-dir "<NEW_DIRECTORY>"
```

**Приклад:**

```powershell
.\totenkahn.exe ci revisions --repo 'C:\TotenkahnBuild\source' --baseline 6407d024d5202e3fd5418d8e28968c887e7c305f --candidate 5a9659d7d39d9c9e0a2c8780f4abcb3e2b7ff2e9 --output-dir 'C:\Reports\rule-revisions-01'
```

Це історичні коміти лабораторного приймання; для власної зміни вкажіть SHA свого baseline і candidate. Команда не виконує код candidate, Atomic чи мережевий збір. Вихідні файли й звіти зберігаються в новому каталозі. За потреби `--contract` задає інший переглянутий контракт із baseline.

**Що перевірити:** `baseline_commit`, `candidate_commit`, `decision`, кількість `regressed`, `not_met`, `insufficient` і докази окремих випадків. Код завершення: `0` — passed, `1` — відхилений кандидат, `2` — помилка, `3` — потрібна перевірка. Невідомі або відсутні потрібні дані не прирівнюються до підтвердженого NO MATCH.

### Автоматична перевірка pull request

Workflow `rule-revisions.yml` запускає перевірку правила на GitHub-hosted runner. Baseline — коміт базової гілки PR, candidate — коміт гілки зі змінами, а не тимчасовий merge-коміт GitHub. Окремий `ci.yml` перевіряє вихідний код на Linux і Windows.

**Порядок запуску:**

1. Спочатку прийміть інфраструктуру CI та переглянуті baseline-очікування в основну гілку.
2. Створіть гілку зі зміною правила, запуште її та відкрийте pull request.
3. Перегляньте перевірки `TOTENKAHN source and detection CI` та `Totenkahn - Versioned rule gate`.
4. Порівняйте звіт із задумом зміни перед merge. Зміни workflow або baseline-політики також потребують review.

**Приклад:** у лабораторному `examples/rule-ci/rule.yaml` заміна `_POSITIVE` на `_NEVER_EXECUTED` має відхилити candidate з однією регресією. Після негативного тесту відновіть правило й дочекайтеся успішної перевірки.

**Що перевірити:** фактичні SHA, звіти rule gate та точну причину відхилення. `ci-windows-…zip` — архів звітів, а не Windows-програма. Для PR-перевірок не потрібні Elastic secrets, self-hosted runner або виконання дій на сервері.

### Живе приймання через Elastic

Ручний workflow `elastic-live-revisions.yml` спочатку виконує офлайн-перевірку версій правил. Лише після успіху створює дві контрольовані команди `cmd.exe /d /c echo` на лабораторному хості, отримує свіжі процесні події через Elastic API й перевіряє п'ять етапів обробки.

**Налаштування та запуск:**

1. Додайте шаблон із `examples/ci-workflows/elastic-live-revisions.yml` у `.github/workflows/` довіреного лабораторного репозиторію.
2. Узгодьте всі шляхи `release-discover-ci` у шаблоні з каталогом перевіреної програми, а також локальні шляхи CA та curl. Шаблон не вибирає активну delivery-версію автоматично.
3. Налаштуйте runner із мітками `self-hosted`, `Windows`, `X64`, `totenkahn-lab`.
4. Задайте repository variables `ELASTIC_URL`, `ELASTIC_CONNECT_IP`, `ELASTIC_PROCESS_INDEX`, `ELASTIC_HOST_ID` і secret `ELASTIC_API_KEY`. Наявний контракт очікує HTTPS `https://es01:9200`, перевірений CA та індекс `logs-endpoint.events.process-*`.
5. Для іншого source repository задайте `TOTENKAHN_RULE_REPOSITORY`. Якщо він приватний, додайте `TOTENKAHN_RULES_READ_TOKEN` лише з доступом читання потрібного репозиторію.
6. В **Actions → Totenkahn - Versioned live Elastic acceptance → Run workflow** введіть повні SHA `baseline` і `candidate`.

**Приклад:** baseline `6407d024d5202e3fd5418d8e28968c887e7c305f`, candidate `5a9659d7d39d9c9e0a2c8780f4abcb3e2b7ff2e9` — пара, перевірена в лабораторії. Для нового правила потрібні відповідні переглянуті сценарій і очікування; два echo-маркери не перевіряють довільну техніку.

**Що перевірити:** 2 імпортовані події, 1 MATCH / 1 NO MATCH у Sigma та Hunting, 2 події timeline, PASS правильного candidate та рівно 1 регресію для навмисно зіпсованого контролю. У `live-provenance.json` мають збігатися хост, PID, маркер, час та хеш оригінальної API-відповіді. Повні результати залишаються на runner у `ci-runs\live-revisions-<RUN_ID>-<ATTEMPT>.zip`. Це перевірка телеметрії й логіки детекції, не спрацювання EDR-алерту та не публікація правила в Elastic/Splunk.

Деталі контракту й інфраструктури: [examples/rule-ci/README.md](examples/rule-ci/README.md).

## 28. CD: доставка, активація та rollback

Зберігає перевірені Windows-збірки поруч і перемикає активну версію після серверного офлайн-тесту та згоди оператора. Каталог інструмента `totenkahn-setup.exe`, вхідний пакет, сховище версій і дані користувача мають бути відокремлені.

Приклади нижче виконуються з каталогу **повного перевіреного інструмента доставки**. `--root` у всіх командах має бути однаковим. Без нього використовується сховище `totenkahn-delivery` у стандартному локальному каталозі даних поточного користувача.

### Отримання Windows-пакета

Створює обидва `.exe`, перевіряє збірку та експортує пакет зі звітами. Вручну запустіть **Actions → TOTENKAHN Windows candidate → Run workflow** на переглянутій гілці.

**Приклад пакета:** артефакт `totenkahn-windows-candidate-<COMMIT>` містить внутрішній `totenkahn-windows-candidate.zip`, `SHA256SUMS`, `RELEASE_SHA256SUMS`, `delivery-review.json` та звіти приймання. Зовнішній ZIP GitHub потрібно розпакувати першим; `.exe` розташовані у внутрішньому ZIP.

**Команда перевірки внутрішнього архіву:**

```powershell
Get-FileHash -LiteralPath 'C:\TotenkahnServer\incoming-delivery\totenkahn-windows-candidate.zip' -Algorithm SHA256
```

Порівняйте хеш із підсумком довіреного build run. Після збігу розпакуйте **весь** внутрішній ZIP у новий каталог:

```powershell
Expand-Archive -LiteralPath 'C:\TotenkahnServer\incoming-delivery\totenkahn-windows-candidate.zip' -DestinationPath 'C:\TotenkahnServer\candidate'
```

**Що перевірити:** `build_status`, `acceptance_status`, `limitations`, походження в `build-provenance.json` та обидва `.exe`. `passed_with_warnings` не приховує відсутність модулів Atomic або неперевірені live-сценарії. SHA-256 перевіряє байти, але сам по собі не засвідчує видавця.

### Перевірка й підготовка версії

`inspect` перевіряє вхідний release без копіювання. `stage` копіює його в окремий слот і повторно перевіряє файли. Ідентифікатор версії — SHA-256 файла `release-manifest.json`, **не ZIP-архіву**.

**Синтаксис:**

```powershell
.\totenkahn-setup.exe delivery inspect --release-dir "<RELEASE_DIRECTORY>" --expected-sha256 <REVIEWED_MANIFEST_SHA256>
.\totenkahn-setup.exe delivery stage --root "<STORE>" --release-dir "<RELEASE_DIRECTORY>" --expected-sha256 <REVIEWED_MANIFEST_SHA256>
```

**Приклад:** після незалежного порівняння `RELEASE_SHA256SUMS` із підсумком build run прочитайте його значення:

```powershell
$releaseId = ((Get-Content -LiteralPath 'C:\TotenkahnServer\incoming-delivery\RELEASE_SHA256SUMS' -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
.\totenkahn-setup.exe delivery stage --root 'C:\TotenkahnServer\delivery-store' --release-dir 'C:\TotenkahnServer\candidate' --expected-sha256 $releaseId
```

**Що перевірити:** PASS, правильний `release_id`, `active_changed: false`. Наявний слот не перезаписується. Помилка копіювання або цілісності не активує candidate.

### Серверний тест доставленої версії

Перевіряє запуск обох `.exe` та всі п'ять офлайн-етапів з двадцятьма іменованими перевірками. Використовує ізольовані синтетичні дані, без Atomic та зовнішніх сервісів.

**Синтаксис:**

```powershell
.\totenkahn-setup.exe delivery test --root "<STORE>" --release <RELEASE_ID> [--timeout <SECONDS>]
```

**Приклад:** використовується `$releaseId` із попереднього кроку:

```powershell
.\totenkahn-setup.exe delivery test --root 'C:\TotenkahnServer\delivery-store' --release $releaseId --timeout 600
```

**Що перевірити:** PASS і повернений шлях до `receipt.json`; повний звіт знаходиться поряд у `offline/report.json`. Консоль може не показувати проміжного прогресу: журнали зберігаються у `tests\<ID>`. Receipt зв'язує версію з хешами звіту й журналів. Активація повторно перевіряє ці докази. Нова невдала перевірка не замінює чинну активну версію.

### Явна активація

Перемикає активну версію після перевірки release та збереженого приймання. Оператор має переглянути обмеження збірки й окремі live-докази для свого сценарію.

**Синтаксис:**

```powershell
.\totenkahn-setup.exe delivery activate --root "<STORE>" --release <RELEASE_ID> --reviewer "<OPERATOR>" --reason "<REVIEW_REASON>" --yes
```

**Приклад:**

```powershell
.\totenkahn-setup.exe delivery activate --root 'C:\TotenkahnServer\delivery-store' --release $releaseId --reviewer Engineer --reason 'Lab activation; offline acceptance reviewed; live limitations acknowledged.' -y
```

`-y` і `--yes` означають явну згоду. Причина є записом рішення оператора, а не автоматичним доказом живого приймання.

**Що перевірити:** PASS, `active`, `previous` та запис `activate` в історії. При першій активації попередньої версії немає.

### Стан і запуск активної програми

Перевіряє активний release та запускає саме його. Аргументи після `--` передаються програмі без зміни.

**Синтаксис:**

```powershell
.\totenkahn-setup.exe delivery status --root "<STORE>" [--json]
.\totenkahn-setup.exe delivery run --root "<STORE>" -- <APPLICATION_COMMAND_AND_ARGUMENTS>
```

**Приклад:**

```powershell
.\totenkahn-setup.exe delivery status --root 'C:\TotenkahnServer\delivery-store'
.\totenkahn-setup.exe delivery run --root 'C:\TotenkahnServer\delivery-store' -- dump profiles
```

**Що перевірити:** потрібний `active` і успішне виконання команди. Прямий запуск іншої копії `totenkahn.exe` не перевіряє механізм active selection. `TOTENKAHN_HOME` зберігається; без нього використовуються стандартні дані поточного користувача. Дані не повинні розміщуватися всередині delivery store. Під час `delivery run` сховище заблоковане для одночасної активації чи rollback.

### Повернення попередньої прийнятої версії

Rollback повторно перевіряє попередній release та його докази приймання, після чого перемикає active. Потрібні дві різні версії, які вже були протестовані й активовані.

**Синтаксис:**

```powershell
.\totenkahn-setup.exe delivery rollback --root "<STORE>" [--release <EXPECTED_PREVIOUS_ID>] --reviewer "<OPERATOR>" --reason "<REASON>" --yes
```

**Приклад:**

```powershell
.\totenkahn-setup.exe delivery rollback --root 'C:\TotenkahnServer\delivery-store' --reviewer Engineer --reason 'Controlled return to the previous accepted release.' -y
.\totenkahn-setup.exe delivery status --root 'C:\TotenkahnServer\delivery-store'
.\totenkahn-setup.exe delivery run --root 'C:\TotenkahnServer\delivery-store' -- dump profiles
```

Для суворої перевірки цілі додайте `--release` із заздалегідь переглянутим ID попередньої версії.

**Що перевірити:** active повернувся до попереднього ID, previous вказує на щойно замінену версію, в історії є `rollback`, програма запускається. Обидва слоти й дані залишаються на місці. Rollback не скасовує зміни аудиту, дії Atomic, підготовку залежностей або міграції даних.

### Ручний workflow доставки

Шаблон `examples/ci-workflows/controlled-delivery.yml` запускається лише через `workflow_dispatch` на довіреному лабораторному runner. Він використовує окремий перевірений інструмент доставки та вже перенесений оператором пакет.

**Порядок запуску:** перенесіть шаблон у `.github/workflows/` лабораторного репозиторію, узгодьте шляхи, запустіть `stage-test`, перегляньте результати, а потім окремо `activate`. Для повернення використайте `rollback` з ID очікуваної попередньої версії.

**Приклад параметрів:** `operation: stage-test`, `release_id`: переглянутий SHA-256 маніфесту, `reason`: мета лабораторного приймання. Для `activate` і `rollback` reason має описувати рішення та враховані обмеження.

**Що перевірити:** підсумок job і локальний стан сховища. Телеметрія не завантажується в GitHub. Доставка застосунку не розгортає правила в SIEM/EDR. Детальний порядок: [docs/CONTROLLED_DELIVERY.md](docs/CONTROLLED_DELIVERY.md).

## 29. Реліз v0.1.0

[Опис релізу, докази приймання та відомі обмеження v0.1.0](docs/RELEASE_NOTES_v0.1.0.md).
