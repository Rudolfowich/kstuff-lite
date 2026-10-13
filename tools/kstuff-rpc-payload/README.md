# kstuff-rpc

Отдельный userland-payload для PS5: открывает TCP-сервер (`:9030`) и
позволяет с хоста дёргать `kekcall`-примитивы kstuff (read/write памяти
ядра, raw kekcall) из Python без пересборки kstuff.

Требует, чтобы **kstuff уже был загружен** (UELF установлен — иначе kekcall
не существует как syscall).

## Файлы

- `src/main.c` — payload (TCP-сервер + inline kekcall-ABI)
- `Makefile` — сборка через `ps5-payload-sdk`
- `../kstuff_rpc.py` — host-side Python-клиент

## Требования

- `ps5-payload-sdk` установлен (ожидается `/opt/ps5-payload-sdk`)
- на macOS clang-wrapper требует `LLVM_CONFIG` на внешний `llvm-config`
  (например `brew install llvm@23`)
- PS5 c kstuff в сети, pldmgr (PLK) слушает на `:8084`

## Сборка

```bash
cd tools/kstuff-rpc-payload
make
# или с явными путями:
PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk \
LLVM_CONFIG=/opt/homebrew/opt/llvm@23/bin/llvm-config \
make
```

На выходе: `kstuff-rpc.elf` (~100 KB).

## Залив и запуск (pldmgr HTTP API, порт 8084)

Два вызова: сначала `POST /manage:upload`, потом `GET /loadpayload:<name>`.

```bash
PS5=192.168.2.2
ELF=kstuff-rpc.elf

# upload
curl -X POST \
  -H "Content-Type: application/octet-stream" \
  --data-binary @$ELF \
  "http://$PS5:8084/manage:upload?filename=$ELF"

# launch
curl "http://$PS5:8084/loadpayload:$ELF"
```

После запуска в klog (`192.168.2.2:3232`) должно быть:
```
[kstuff-rpc] kekcall ok, kbase=0xffffffff...
[kstuff-rpc] listening on 0.0.0.0:9030
```

## Проверка

```bash
python3 tools/kstuff_rpc.py 192.168.2.2
# PING ok
# kbase = 0xffffffff...
# [0xffffffff...] = 0x...
```

## Использование из Python

```python
from kstuff_rpc import Client, KEKCALL_SCAN_CDEVSW, KEKCALL_WRITE64

with Client("192.168.2.2") as c:
    c.ping()
    kbase = c.kbase()
    data = c.read(kbase, 0x100)         # до 1 MiB за вызов
    val = c.read_u64(kbase + 0x10)
    c.write64(kbase + 0x100, 0xdeadbeef)  # qword
    c.write(kbase + 0x100, b"\x00" * 16)  # кратно 8
    rc = c.kekcall(KEKCALL_SCAN_CDEVSW, 0, 0, 0)   # любой kekcall
    # c.exit_server()  # погасить сервер (payload завершится)
```

## Протокол (reference)

Little-endian, без выравнивания:
- Request: `u32 cmd, u32 arg_len, bytes[arg_len]`
- Response: `i64 status, u32 resp_len, bytes[resp_len]`

| cmd  | имя     | args                            | resp              |
|------|---------|---------------------------------|-------------------|
| 0x01 | PING    | ()                              | `"PONG"`          |
| 0x02 | READ    | `u64 kaddr, u32 len`            | `bytes[len]`      |
| 0x03 | WRITE   | `u64 kaddr, bytes` (len % 8 == 0)| ()                |
| 0x04 | WRITE64 | `u64 kaddr, u64 value`          | ()                |
| 0x05 | KEKCALL | `u32 nr, u64 a1,a2,a3`          | `i64 ret`         |
| 0x06 | KBASE   | ()                              | `u64 kbase`       |
| 0x07 | EXIT    | ()                              | () — глушит сервер |

READ использует `KEKCALL_DUMP_MEM` (мягкий — unmapped qwords возвращаются
как нули). WRITE/WRITE64 используют `KEKCALL_WRITE64`.

## Цикл правок

```bash
# 1. правишь src/main.c
# 2. пересобираешь:
make
# 3. грузишь:
curl -X POST -H "Content-Type: application/octet-stream" \
  --data-binary @kstuff-rpc.elf \
  "http://192.168.2.2:8084/manage:upload?filename=kstuff-rpc.elf"
curl "http://192.168.2.2:8084/loadpayload:kstuff-rpc.elf"
# 4. тестируешь с хоста
python3 ../kstuff_rpc.py 192.168.2.2
```

kstuff **не трогается** — остаётся загруженным, UELF никуда не денется.

## Диагностика

- **`Connection refused` на `:9030`** — payload не запустился или сам
  закрылся. Смотри klog (`:3232`): если видишь `kekcall sanity FAILED`,
  значит UELF не поставлен или мы в не-kstuff-окружении.
- **`:9030` открыт, но клиент падает** — проверь версию протокола и
  номера kekcall'ов. Таблица номеров зашита в `src/main.c` и в
  `kstuff_rpc.py` — они должны совпадать с `ps5-kstuff-ldr/src/kekcall.h`.
- **Payload висит** — следующий upload+loadpayload перезапустит его
  (pldmgr разрешает параллельные процессы).
