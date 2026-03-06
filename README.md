# RNode-Halow

[🇬🇧 English](#english) | [🇷🇺 Русский](#русский)


Coverage map: https://map.rnode-halow.ru/

---

## English

### Implemented Features

The following is currently implemented:

- Broadcast packet transmission and reception over LMAC WiFi HaLow
- DHCP client or static IP
- Real-time statistics
- Frequency and modulation parameter selection
- TCP server
- OTA firmware update (unencrypted)
- Confirmed compatibility with RNS and its extensions — Meshchat, Sideband
- LBT (Listen Before Talk)
- Airtime limiting

### What Is Currently Missing

- Stability — the project is in early development
- RNS stack — the device is a TCP modem only
- USB and SDIO connection support not implemented
- The LMAC stack remains a mystery; ideally the proprietary libs would be replaced

### Default Parameters

- **Frequency:** 866–867 MHz (1 MHz channel width)
- **PHY:** WiFi MCS0
- **Power:** 17 dBm
- **TCP Port:** 8001

### Flashing

> **WARNING!** Before flashing, it is recommended to disassemble one of the devices and dump the SPI flash. Do not cut power during the flashing process. For the first flash, the device must be on the same local network as your PC.

1. Launch `RNode-HaLow Flasher.exe`
2. Select the firmware version to install (it will be downloaded automatically from GitHub), or select a local firmware file
3. Select the target device from the list; type `hgic` refers to devices with original firmware
4. Start the flashing process. It doesn't always succeed on the first try — restart if needed
5. Once `"OK flash done"` appears in the console, the firmware is written and the device can be disconnected

<img width="968" height="1119" alt="image" src="https://github.com/user-attachments/assets/9a2c8310-06eb-45e2-8b96-3638ed505c0a" />


### Initial Setup

After flashing, the device obtains an IP address via DHCP. You can either double-click it in `RNode-HaLow Flasher.exe`, or navigate to the assigned IP in any browser.

### Dashboard

- **RX/TX Bytes, Packets, Speed** — self-explanatory
- **Airtime** — percentage of time the device is transmitting
- **Channel Utilization** — how busy the airwaves are
- **Noise Floor Power Level** — approximate noise level

### Device Settings

#### RF Settings

- **TX Power** — transmitter output power, max 20 dBm
- **Central Frequency** — operating frequency
- **MCS Index** — modulation/coding scheme; MCS0 has the longest range, MCS7 is the fastest. MCS10 is theoretically the most range-efficient but currently only MCS0 works reliably
- **Bandwidth** — channel width; currently only 1 and 2 MHz work
- **TX Super Power** — increases transmitter power (theoretically up to 25 dBm); long-term safety is unknown

#### Listen Before Talk

All devices support LBT by default. You can additionally limit the maximum airtime the device occupies to reduce collisions. 30–50% is optimal.

#### Network Settings

If you don't know what this is for, leave it alone — you can lock yourself out.

#### TCP Radio Bridge

By default, anyone can connect to the TCP port and send data directly over the air. To restrict this, set a whitelist of devices allowed to connect to the socket. Examples:

- `192.168.1.0/24` — allow all devices on the 192.168.1.x subnet
- `192.168.1.X/32` — allow only a single specific device

The **Client** field shows who is currently connected to the socket; only one connection at a time is allowed. Refreshes only on page reload.

### Reticulum Configuration

Add the following to your Reticulum interfaces config. The IP address can be found via your router's DHCP server — the device hostname is `RNode-Halow-XXXXXX`, where `XXXXXX` is the last 3 bytes of the MAC address, or via `RNode-HaLow Flasher.exe`.

    [[RNode-Halow]]
      type = TCPClientInterface
      enabled = yes
      target_host = 192.168.XXX.XXX
      target_port = 8001

### Meshchat Setup

Go to **Interfaces** → **Add Interface** → type **TCP Client Interface** → enter the node IP in **Target Host**, port `8001` (or as configured in the web configurator).

<img width="570" height="593" alt="image" src="https://github.com/user-attachments/assets/d524da22-9a19-46bf-a187-aec61b444c5a" />


### Sideband Setup

Go to **Connectivity** → **Connect via TCP** → enter the node IP in **Target Host**, port `8001` (or as configured in the web configurator).

<img width="543" height="449" alt="image" src="https://github.com/user-attachments/assets/0e0b5456-d7bd-49c9-a009-d92f3819d335" />


### For Developers

To get started quickly, install the Taixin CDK and open the project in the `project` folder. All necessary tooling is included in CDK.

Logs are output via UART (IO12, IO13) at **2,000,000 baud** (blocking logs).

For full debugging, use a Blue Pill flashed as CKLink. The chip **must** be STM32F103C8 — C6 will not work, and Chinese suppliers often ship rejected/cloned chips with broken USB.

OTA firmware is generated automatically at `project/out/XXX.tar` after building the project.

---

## Русский

# RNode-Halow

## Реализованный функционал

На текущий момент реализовано следующее:
* Передача и прием широковещательных пакетов по LMAC WiFi Halow
* DHCP клиент или статический IP
* Статистика в реальном времени
* Выбор частоты, параметров модуляции
* TCP сервер
* Прошивка/обновление по OTA (незашифровано)
* Подтверждена работоспособность с rns и его надстройками - meshchat, sideband
* LBT
* Ограничение airtime

Что на данный момент отсутсвует:
* Стабильность - проект на ранней стадии разработки
* RNS стек - устройство является только TCP модемом
* Не реализована поддержка подключения по USB, SDIO
* LMAC стек остается загадкой, по хорошему избавиться от проприетарных либ

## Стандартные параметры

Частота 866-867 МГц (ширина канала 1МГц)

PHY WiFi - MCS0

Мощность - 17dBm

Порт TCP - 8001

## Прошивка

ВНИМАНИЕ! Перед прошивкой рекомендуется разобрать одно из устройств и снять дамп SPI флешки! Во время процесса прошивки питание не отключать. Для корректной первой прошивки устройство должно находиться в той же локальной сети, что и ПК

0) Запустить [RNode-HaLow Flasher.exe](https://github.com/I-AM-ENGINEER/RNode_Halow_Firmware/releases/)
1) Выбрать устанавливаемую версию, которая будет автоматически скачана с гитхаба, либо сам файл прошивки 
2) Выбрать прошиваемое устройство из списка, тип hgic - устройства с оригинальной прошивкой
3) Запустить процесс прошивки. Не всегда проходит с первого раза, иногда требуется перезапустить
4) После появления в консоли сообщения "OK flash done" прошивка зашита и устройство можно отключать

<img width="1400" height="1026" alt="image" src="https://github.com/user-attachments/assets/0e1b243b-f1b3-4c7e-a34e-79f845c163ed" />

## Первичная настройка

После прошивки устройство получает IP адрес по DHCP, можно либо 2 раза нажать на него в [RNode-HaLow Flasher.exe](https://github.com/I-AM-ENGINEER/RNode_Halow_Firmware/releases/), или перейти по указанному IP в любом браузере.

<img width="968" height="1119" alt="image" src="https://github.com/user-attachments/assets/9a2c8310-06eb-45e2-8b96-3638ed505c0a" />

### Dashboard

* RX/TX Bytes, packets, speed - понятно по названию
* Airtime - процент времени, которое устройство передает в эфир
* Channel utilization - насколько эфир загружен
* Noise floor power level - приблизительный уровень шумов

### Device Settings

#### RF Settings

* TX Power - выходная мощность передатчика, макс 20 dBm
* Central frequency - частота работы
* MCS index - тип кодировки, MCS0 - самый дальнобойный, MCS7 - самый быстрый. Теоретически самый дальнобойный MCS10, но на текущий момент нормально работает только MCS0
* Bandwidth - ширина канала, на текущий момент работает только 1 и 2 МГц
* TX Super Power - увеличивает мощность передатчика (в теории до 25 dBm), насколько безопасно долговременно использовать - неизвестно

#### Listen Before Talk

Все устройства по умолчанию поддерживают LBT, но дополнительно можно ограничить максимальное время, которое устройство будет занимать радиоэфир для уменьшения колизий. Оптимально 30-50%

#### Network Settings

Если не знаете зачем надо, лучше не трогать, есть возможность заблокировать себе доступ

#### TCP Radio Bridge

По умолчанию любой может подключиться к TCP порту и слать данные напрямую в эфир, что бы это ограничить, рекомендуется установить белый список устройств, которые могут подключиться по данному сокету. Возможные варианты конфигурации:

192.168.1.0/24 - разрешить всем из локальной сети
192.168.1.X/32 - разрешить только одному устройству

В поле client пишется кто подключен к данному сокету в текущий момент, подключение может быть только одно. Обновляется только при обновлении страницы


## Настройка Reticulum через конфиг

Дастаточно в интерфейсы вписать конфиг нового TCPClientInterface интерфейса.

IP адресс можно узнать через DHCP сервер на роутере - устройство имеет hostname "RNode-Halow-XXXXXX", где XXXXXX - последние 3 байта MAC адреса или через [RNode-HaLow Flasher.exe](https://github.com/I-AM-ENGINEER/RNode_Halow_Firmware/releases/)

```
  [[RNode-Halow]]
    type = TCPClientInterface
    enabled = yes
    target_host = 192.168.XXX.XXX
    target_port = 8001
```

## Настройка Meshchat

Перейти во вкладку "Interfaces" -> "Add Interface" -> тип "TCP Client Interface" -> ввести IP ноды в поле "Target Host", порт 8001, или настроенный в веб конфигураторе

<img width="570" height="593" alt="image" src="https://github.com/user-attachments/assets/d524da22-9a19-46bf-a187-aec61b444c5a" />

## Настройка Sideband

Перейти во вкладку "Connectivity" -> "Connect via TCP" -> ввести IP ноды в поле "Target Host", порт 8001, или настроенный в веб конфигураторе

<img width="543" height="449" alt="image" src="https://github.com/user-attachments/assets/0e0b5456-d7bd-49c9-a009-d92f3819d335" />


## Для разработчиков

Для простого старта достаточно поставить Taixin CDK и открыть проект в папке "project". Весь необходимый инструментарий содержится в CDK.

Логи идут по UART (IO12, IO13) со скоростью 2'000'000 бод, т.к. логи блокирующие

Для полноценной отладки используется Blue Pill прошитая в CKLink. Чип обязательно должен быть STM32F103C8, C6 не подойдет + китайцы любят пихать отбраковку/клоны с неработающим USB.

Прошивка для OTA генерируется автоматически project/out/XXX.tar после сборки проекта.

автоматически `project/out/XXX.tar` после сборки проекта.
```
