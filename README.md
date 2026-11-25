# tiktok-appealer

Автономный инструмент для мгновенного HTTP-аудита и безопасного 3-канального снятия ограничений рекомендаций TikTok (**как по-постовых флагов `Ineligible for the For You feed` в TikTok Studio, так и аккаунтного ограничения `Account ineligible for recommendation` во вкладке `System notifications → Account updates`**) без отправки аккаунтов в теневой бан.

## Что под капотом

1. **Прямой опрос регионального мобильного шлюза кластера (`0` запусков браузера при проверке):**
   - Автоопределение домашнего шлюза по `store-idc` / `tt-target-idc` (`api16-normal-no1a.tiktokv.eu`, `api16-normal-c-alisg.tiktokv.com`, `api16-normal-us.tiktokv.us` и др.):
     - `GET /aweme/v1/notice/count/?aid=1233&source=1` — активные группы `filter_type=33` (`Account updates`).
     - `GET /aweme/v1/notice/multi/?aid=1233&group_list=...` (`group=47, 661` и системные группы) — достаёт карточки `Account ineligible for recommendation`, плашку `Update your account region` и историю недавних входов.
     - `GET /api/violation/v1/get_violation_detail` — точный статус (`1 = Effecting`, `4 = Appealing`, `6 = AppealSuccess`, `7 = AppealFailed`), `CanAppeal`, фильтр `bric_social` и `AppealId`.
2. **Три канала апелляции (быстрый HTTP + ленивый браузерный фоллбэк):**
   - **Аккаунт / Уведомления (`group=47/661`):** `POST /api/violation/v1/commit_appeal` → `POST /aweme/v2/appeal/commit/` → фоллбэк `POST https://www.tiktok.com/tns-api/appeal/post-commit` в мобильном `BytedanceWebview` контексте с проверкой перехода в `Appealing` / `AppealSuccess`.
   - **Посты в TikTok Studio:** `POST /tiktok/creator/manage/item_list/v1/` → `/mod/v1/getPenaltyDetails/` и `/api/moderation/penalties/gettransparencypagecontent` → подача через `POST /mod/v1/submitAppeals` и `POST /api/moderation/penalties/submitappeal` с рандомной паузой `8.5–17.5с` между постами.
3. **Встроенный Outlook Hub (`outlook_hub.py`) и мультиформатные сессии:**
   - Поддерживает TOTP 2FA аккаунты (`username|password|email|totp[|proxy]`), аккаунты на почтах Outlook/Hotmail с резервной почтой и 2FA почты (`login:pass:outlook_email:outlook_pass:rec_email:rec_pass:hotmail_2fa`), а также готовые куки `sessions/<username>/cookies.json` и Kintaro-сессии `sessions/<username>.json`.
4. **Чистка отклонённых постов (`--hide-rejected`):**
   - Автоматически переводит посты со статусом `FAILED` в `Private` (`visibility_type=2`), чтобы накопление отклонённых видео не вызывало 30-дневный бан рекомендаций на весь аккаунт (`punish_type=2048`).

## Установка

```bash
pip install -r requirements.txt
```

## Поддерживаемые форматы строк

```text
# 1. TOTP формат (прокси 5-м полем или через --proxy)
username|password|email|BASE32TOTP|socks5://user:pass@ip:port

# 2. Outlook-Hub формат (Microsoft Graph OAuth2 + Hotmail 2FA + доп. почта IMAP)
login:pass:mail@outlook.com:mail_pass:rec@polosmail.com:rec_pass:HOTMAIL2FA

# 3. Уже сохранённая сессия в sessions/<username>/cookies.json или sessions/<username>.json
username
```

## Примеры запуска

```bash
# 1. Мгновенный HTTP-аудит ограничений, региона и постов Studio
python3 main.py check 'user|pass|mail@gmail.com|BASE32TOTP|ip:port:user:pass'

# 2. Снять все ограничения на аккаунте и постах (+ скрыть FAILED посты в Private)
python3 main.py appeal 'login:pass:mail@outlook.com:mail_pass:rec@polosmail.com:rec_pass:HOTMAIL2FA' \
  --proxy 'socks5://user:pass@host:port' --hide-rejected

# 3. Фоновый сторож пачки аккаунтов после залива (опрос по кукам раз в 95–165 сек без повторных логинов)
python3 main.py watch accounts.txt --file --proxy 'socks5://user:pass@host:port' --cycles 0 --hide-rejected
```
