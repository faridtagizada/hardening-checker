# Linux Hardening Checker

Linux sisteminin təhlükəsizlik konfiqurasiyasını **yalnız oxuyaraq** yoxlayan Python aləti. SSH, kritik fayl icazələri, istifadəçi hesabları, kernel parametrləri, təhlükəli servislər və firewall üzrə 20 yoxlama aparır, hər problem üçün düzəliş əmri təklif edir və 0-100 arası hardening xalı hesablayır. Yoxlamalar CIS Benchmark tövsiyələrindən ilhamlanıb.

> Alət sistemdə **heç nəyi dəyişmir**. Yalnız konfiqurasiya fayllarını və `systemctl is-active` nəticəsini oxuyur. Bəzi yoxlamalar (məs. `/etc/shadow`) üçün `sudo` lazımdır, əks halda `SKIP` olur.

## Yoxlamalar
| Kateqoriya | ID | Nə yoxlanır |
|---|---|---|
| SSH | SSH-001..005 | `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, `X11Forwarding`, `MaxAuthTries` |
| Fayl icazələri | FILE-001..005 | `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, `sshd_config` (rejim və sahib) |
| İstifadəçilər | USR-001..003 | UID 0 olan əlavə hesab, boş parollu hesab, parol ömrü (`PASS_MAX_DAYS`) |
| Kernel | SYS-001..005 | `ip_forward`, `tcp_syncookies`, `accept_redirects`, `icmp_echo_ignore_broadcasts`, ASLR |
| Servislər | SVC-001 | telnet, rsh, rlogin, vsftpd, tftpd, xinetd, ypserv aktiv deyil |
| Firewall | FW-001 | `ufw` / `firewalld` / `nftables` aktivdir |

## Xüsusiyyətlər
- `sshd_config` parserı sshd kimi davranır: **ilk təyin olunan dəyər qüvvədədir**, `Include` (drop-in fayllar) dəstəklənir, `Match` blokları nəzərə alınmır
- Hər nəticə: status (PASS/FAIL/WARN/SKIP), ciddilik, detal və **düzəliş əmri**
- Ciddiliyə görə çəkili xal (critical/high/medium/low)
- Çıxış: rəngli terminal, JSON, HTML hesabat
- `--fail-on` ilə CI/CD üçün çıxış kodu (2 = tələb olunan ciddilikdə FAIL var)
- `--root` ilə saxta fayl sistemi üzərində test, real sistemə toxunmadan demo
- `pytest` testləri (9 test)

## Quraşdırma
```bash
git clone https://github.com/<istifadəçi_adın>/hardening-checker.git
cd hardening-checker
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```
Əlavə kitabxana lazım deyil (yalnız testlər üçün `pytest`). Python 3.8+, Linux.

## İstifadə
```bash
# Öz sistemini yoxla (tam nəticə üçün sudo)
sudo python -m hardening_checker

# Yalnız SSH və fayl yoxlamaları
python -m hardening_checker --only SSH,FILE

# JSON + HTML hesabat
sudo python -m hardening_checker --json report.json --html report.html

# CI üçün: yüksək və ya kritik FAIL varsa kod 2 qaytar
python -m hardening_checker --fail-on high

# Demo: qəsdən zəif saxta sistem
python samples/make_demo_root.py /tmp/demo_insecure
python -m hardening_checker --root /tmp/demo_insecure
```

| Parametr | Təsvir |
|---|---|
| `--root` | Fayl sisteminin kökü (default `/`) |
| `--only` | ID prefikslərini filtr et, məs. `SSH,USR` |
| `--json` / `--html` | Hesabat faylları |
| `--fail-on` | `low` / `medium` / `high` / `critical` |
| `--no-color` | Rəngsiz çıxış |

### Nümunə çıxış (zəif demo sistem, SSH və USR yoxlamaları)
```
[FAIL] SSH-001  Root SSH girişi qadağandır
           ↳ root birbaşa SSH ilə daxil ola bilər
           ✎ Düzəliş: PermitRootLogin no
[FAIL] SSH-002  SSH parol autentifikasiyası söndürülüb
           ↳ Parol ilə giriş açıqdır
           ✎ Düzəliş: PasswordAuthentication no (əvvəl SSH açarı qur!)
[FAIL] SSH-003  Boş parola icazə verilmir
           ↳ Boş parollu hesablar daxil ola bilər
           ✎ Düzəliş: PermitEmptyPasswords no
[WARN] SSH-004  X11 forwarding söndürülüb
           ↳ X11Forwarding yes
           ✎ Düzəliş: X11Forwarding no
[WARN] SSH-005  MaxAuthTries ≤ 4
           ↳ MaxAuthTries=10
           ✎ Düzəliş: MaxAuthTries 3
[FAIL] USR-001  Yalnız root-un UID-si 0-dır
           ↳ UID 0 olan əlavə hesablar: toor
           ✎ Düzəliş: Bu hesabları sil və ya UID-ni dəyiş: sudo usermod -u <yeni> <ad>
[FAIL] USR-002  Boş parollu hesab yoxdur
           ↳ Boş parollu hesablar: guest
           ✎ Düzəliş: sudo passwd -l <ad>  (kilidlə) və ya parol təyin et
[WARN] USR-003  Parolun maksimum ömrü ≤ 90 gün
           ↳ PASS_MAX_DAYS=99999
           ✎ Düzəliş: /etc/login.defs: PASS_MAX_DAYS 90

Nəticə: 0 PASS, 5 FAIL, 3 WARN, 0 SKIP
Hardening xalı: 11/100
```
> Öz sistemində işlədib real ekran görüntüsü əlavə et.

## Layihə strukturu
```
hardening-checker/
├── hardening_checker/
│   ├── models.py          # Result, Context, xal hesablanması
│   ├── ssh_checks.py      # sshd_config parser və SSH yoxlamaları
│   ├── file_checks.py     # fayl icazələri
│   ├── user_checks.py     # hesablar və parol siyasəti
│   ├── system_checks.py   # sysctl, servislər, firewall
│   ├── runner.py          # yoxlamaları işə salır
│   ├── report.py          # terminal / JSON / HTML
│   └── cli.py
├── samples/make_demo_root.py
└── tests/test_checks.py
```

## Testlər
```bash
pytest -v
```
Testlər `samples/make_demo_root.py` ilə yaradılan zəif və təhlükəsiz saxta fayl sistemlərindən və saxta `systemctl` icraçısından istifadə edir, ona görə real sistemdən asılı deyil.

## Məhdudiyyətlər
- Yalnız Debian/Ubuntu tipli standart yollar (`/etc/ssh/sshd_config`, `/etc/login.defs`)
- Firewall yoxlaması servisin aktivliyinə baxır, qaydaların məzmununa yox
- CIS Benchmark-ın tam əvəzi deyil, əsas yoxlamalardır
- Konteynerlərdə `systemd` olmadığı üçün servis/firewall yoxlamaları `SKIP` olur

## Gələcək planlar
- [ ] Əlavə yoxlamalar (`auditd`, `fail2ban`, avtomatik yeniləmələr, world-writable fayllar)
- [ ] Yoxlamaların YAML ilə konfiqurasiyası
- [ ] `--fix` rejimi (təsdiq ilə avtomatik düzəliş)
- [ ] Markdown hesabat

## Lisenziya
MIT
