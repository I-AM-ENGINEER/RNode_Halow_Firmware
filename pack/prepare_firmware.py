#!/usr/bin/env python3
from __future__ import annotations

import argparse
import configparser
import struct
from pathlib import Path


INI_NAME = ""#"makecode.ini"  # фиксированное имя ini рядом со скриптом (если есть)

# Минимальный валидный param-блок (как в factory BIN):
# В 0x200 лежит u16 LE длина, дальше данные. Для твоего param.bin: 04 00 2B 1A.
DEFAULT_PARAM = bytes.fromhex("04 00 2B 1A")
DEFAULT_PARAM_OFFSET = 0x200


def _u8(x: int) -> int:
    return x & 0xFF


def _u16(x: int) -> int:
    return x & 0xFFFF


def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def parse_int(s: str) -> int:
    """
    В этих ini почти всё в HEX без 0x (5A69, 20001000, 1A, 3B...).
    Поддерживаем также 0x....
    """
    s = (s or "").strip()
    if not s:
        return 0
    sl = s.lower()
    if sl.startswith("0x"):
        return int(sl, 16)
    return int(sl, 16)


def hgic_crc32(data: bytes) -> int:
    """
    CRC-32 как в HGIC:
      init 0xFFFFFFFF, reflected, poly 0xEDB88320, final ~crc
    """
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
            crc &= 0xFFFFFFFF
    return (~crc) & 0xFFFFFFFF


def hgic_crc16_modbus(data: bytes) -> int:
    """
    CRC-16/MODBUS как в HGIC:
      poly=0xA001, init=0xFFFF, refin/refout=true, xorout=0x0000
    """
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
            crc &= 0xFFFF
    return crc & 0xFFFF


def load_ini(ini_path: Path) -> tuple[dict, dict]:
    cfg = configparser.ConfigParser(
        interpolation=None,
        delimiters=("=",),
        comment_prefixes=("#", ";"),
        inline_comment_prefixes=("#", ";"),
        strict=False,
    )
    cfg.optionxform = str

    # ini часто не utf-8 (cp1251/ansi)
    last_err: Exception | None = None
    for enc in ("utf-8", "cp1251", "latin-1"):
        try:
            cfg.read(ini_path, encoding=enc)
            last_err = None
            break
        except UnicodeDecodeError as e:
            last_err = e
            continue
    if last_err is not None:
        raise SystemExit(f"Cannot decode INI file: {ini_path}")

    if "COMMON" not in cfg:
        raise SystemExit("INI must contain [COMMON].")

    common = dict(cfg["COMMON"])
    spi = dict(cfg["SPI"]) if "SPI" in cfg else {}
    return common, spi


def _boot_mode_value(spi: dict) -> int:
    pll_src_mhz = parse_int(spi.get("PLL_SRC_MHZ", "1A")) & 0xFF
    pll_en = 1 if parse_int(spi.get("PLL_EN", "0")) else 0
    debug = 1 if parse_int(spi.get("DebugInfoEn", "0")) else 0
    aes_en = 1 if parse_int(spi.get("AesEnable", "0")) else 0
    # В factory BIN crc_en = 1 (бит 11), поэтому по умолчанию включаем.
    crc_en = 1 if parse_int(spi.get("CodeCRC16", "1")) else 0

    mode = (
        (pll_src_mhz & 0xFF)
        | ((pll_en & 1) << 8)
        | ((debug & 1) << 9)
        | ((aes_en & 1) << 10)
        | ((crc_en & 1) << 11)
    ) & 0xFFFF
    return mode


def build_boot_header(spi: dict, code: bytes, code_off: int) -> bytes:
    boot_flag = parse_int(spi.get("Flag", "5A69"))
    version = parse_int(spi.get("Version", "0"))
    size = 0x1C  # BOOT header total = size+4 = 0x20

    boot_to_sram_addr = parse_int(spi.get("CodeLoadToSramAddr", "20001000"))
    run_sram_addr = parse_int(spi.get("CodeExeAddr", "20001000"))
    boot_code_offset_addr = code_off
    boot_from_flash_len = len(code)

    driver_strength = parse_int(spi.get("DriverStrength", "0")) & 0x3
    spi_clk = parse_int(spi.get("SPI_CLK_MHZ", "10")) & 0x3FFF
    boot_baud_mhz_driver_strength = (spi_clk | (driver_strength << 14)) & 0xFFFF

    mode = _boot_mode_value(spi)
    crc_en = 1 if (mode & (1 << 11)) else 0
    boot_data_crc = hgic_crc16_modbus(code) if crc_en else 0

    # flash_blk_size: units 512B when version==0, else 64KB.
    unit = 0x200 if version == 0 else 0x10000
    flash_blk_size = (boot_code_offset_addr // unit) & 0xFFFF

    reserved = 0

    # pack with head_crc16=0
    boot_hdr0 = struct.pack(
        "<HBBIIIIHHHHHH",
        _u16(boot_flag),
        _u8(version),
        _u8(size),
        _u32(boot_to_sram_addr),
        _u32(run_sram_addr),
        _u32(boot_code_offset_addr),
        _u32(boot_from_flash_len),
        _u16(boot_data_crc),
        _u16(flash_blk_size),
        _u16(boot_baud_mhz_driver_strength),
        _u16(mode),
        _u16(reserved),
        _u16(0),
    )
    if len(boot_hdr0) != 0x20:
        raise RuntimeError("BOOT header size mismatch")

    # В factory BIN: head_crc16 = CRC16(header[:0x1E]); CRC16(header_with_crc) == 0.
    head_crc16 = hgic_crc16_modbus(boot_hdr0[:-2])
    return boot_hdr0[:-2] + struct.pack("<H", _u16(head_crc16))


def build_spi_info_header(spi: dict, *, template_raw: bytes | None = None) -> bytes:
    func_code = 0x01

    if template_raw is not None:
        # Берём ровно то, что было в factory BIN (read_cfg + spec), пересчитываем CRC.
        if len(template_raw) < 4:
            raise SystemExit("Bad template SPI header")
        if template_raw[0] != 0x01:
            raise SystemExit("Template SPI header func_code != 0x01")
        size = template_raw[1]
        total = size + 2
        raw = template_raw[:total]
        hdr_wo_crc = raw[:-2]
        header_crc16 = hgic_crc16_modbus(hdr_wo_crc)
        return hdr_wo_crc + struct.pack("<H", _u16(header_crc16))

    read_cmd = parse_int(spi.get("ReadCmd", "03")) & 0xFF
    cmd_dummy = parse_int(spi.get("ReadCmdDummy", "0")) & 0xF
    clock_mode = parse_int(spi.get("ClockMode", "0")) & 0x3
    spec_seq_en = 1 if parse_int(spi.get("SpecSquenceEn", "0")) else 0
    quad_wire_en = 1 if parse_int(spi.get("WireMode4En", "0")) else 0

    cfg1 = (cmd_dummy & 0xF) | ((clock_mode & 0x3) << 4) | ((spec_seq_en & 1) << 6) | ((quad_wire_en & 1) << 7)

    def _wire_mode_bits(v: int) -> int:
        if v == 1:
            return 0
        if v == 2:
            return 1
        if v == 4:
            return 2
        return 0

    wire_cmd = _wire_mode_bits(parse_int(spi.get("WireModeWhenCmd", "1")))
    wire_addr = _wire_mode_bits(parse_int(spi.get("WireModeWhenAddr", "1")))
    wire_data = _wire_mode_bits(parse_int(spi.get("WireModeWhenData", "1")))
    quad_sel = parse_int(spi.get("WireMode4Select", "0")) & 0x3

    cfg2 = (wire_cmd & 0x3) | ((wire_addr & 0x3) << 2) | ((wire_data & 0x3) << 4) | ((quad_sel & 0x3) << 6)

    reserved3 = 0
    sample_delay = parse_int(spi.get("SampleDelay", "0")) & 0xFFFF

    read_cfg = struct.pack("<BBBBH", read_cmd, cfg1, cfg2, reserved3, sample_delay)

    spec = bytearray(64)
    if spec_seq_en:
        n = parse_int(spi.get("SpecSquenceNumbers", "0"))
        out = bytearray()
        for i in range(max(0, n)):
            key = f"SpecSquence{i}"
            hexs = spi.get(key, "").strip()
            if hexs:
                out += bytes.fromhex(hexs)
        spec[: min(64, len(out))] = out[:64]

    # size field excludes first 2 bytes, includes CRC16:
    # total = size+2 = 2 + 6 + 64 + 2 = 74 -> size=72 (0x48)
    size = len(read_cfg) + len(spec) + 2

    hdr_wo_crc = struct.pack("<BB", func_code, _u8(size)) + read_cfg + bytes(spec)
    header_crc16 = hgic_crc16_modbus(hdr_wo_crc)
    return hdr_wo_crc + struct.pack("<H", _u16(header_crc16))


def build_fw_info_header(
    common: dict,
    *,
    code_crc32: int,
    param_crc16: int,
    template_vals: tuple[int, int, int, int, int] | None = None,
) -> bytes:
    # struct hgic_spiflash_header_firmware_info:
    # total = 25, size field = total-2 = 23 (0x17)
    func_code = 0x02
    size = 23

    if template_vals is not None:
        sdk_version, svn_version, date, chip_id, cpu_id = template_vals
    else:
        sdk_version = parse_int(common.get("SDK_VERSION", "1")) & 0xFFFFFFFF
        svn_version = parse_int(common.get("SVN_VERSION", "44F4")) & 0xFFFFFFFF
        date = parse_int(common.get("DATE", "0")) & 0xFFFFFFFF
        chip_id = parse_int(common.get("CHIP_ID", "4002")) & 0xFFFF
        cpu_id = parse_int(common.get("CPU_ID", "1")) & 0xFF

    hdr_wo_crc = struct.pack(
        "<BBIIIHBIH",
        _u8(func_code),
        _u8(size),
        _u32(sdk_version),
        _u32(svn_version),
        _u32(date),
        _u16(chip_id),
        _u8(cpu_id),
        _u32(code_crc32),
        _u16(param_crc16),
    )
    crc16 = hgic_crc16_modbus(hdr_wo_crc)
    return hdr_wo_crc + struct.pack("<H", _u16(crc16))


def _parse_template_headers(template: bytes) -> dict:
    if len(template) < 0x100:
        raise SystemExit("Template too small")

    boot = template[:0x20]
    if boot[:2] != b"\x69\x5A":
        raise SystemExit("Template BOOT flag mismatch")
    if hgic_crc16_modbus(boot) != 0:
        raise SystemExit("Template BOOT CRC16 invalid")

    b = struct.unpack("<HBBIIIIHHHHHH", boot)
    boot_vals = {
        "boot_flag": b[0],
        "version": b[1],
        "size": b[2],
        "boot_to_sram_addr": b[3],
        "run_sram_addr": b[4],
        "code_off": b[5],
        "code_len": b[6],
        "boot_data_crc": b[7],
        "flash_blk_size": b[8],
        "baud_strength": b[9],
        "mode": b[10],
    }

    spi_off = 0x20
    if template[spi_off] != 0x01:
        raise SystemExit("Template SPI func_code != 0x01")
    spi_size = template[spi_off + 1]
    spi_total = spi_size + 2
    spi = template[spi_off : spi_off + spi_total]
    if hgic_crc16_modbus(spi) != 0:
        raise SystemExit("Template SPI CRC16 invalid")

    fw_off = spi_off + spi_total
    if template[fw_off] != 0x02:
        raise SystemExit("Template FW func_code != 0x02")
    fw_size = template[fw_off + 1]
    fw_total = fw_size + 2
    fw = template[fw_off : fw_off + fw_total]
    if hgic_crc16_modbus(fw) != 0:
        raise SystemExit("Template FW CRC16 invalid")

    f = struct.unpack("<BBIIIHBIHH", fw)
    fw_vals = {
        "sdk_version": f[2],
        "svn_version": f[3],
        "date": f[4],
        "chip_id": f[5],
        "cpu_id": f[6],
        "code_crc32": f[7],
        "param_crc16": f[8],
    }

    return {
        "boot": boot_vals,
        "spi_raw": spi,
        "fw": fw_vals,
        "hdr_total": fw_off + fw_total,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Pack HGIC/TXW firmware for SPI boot: headers @0x0000, param @0x200, code @CodeAddrOffset.")
    ap.add_argument("input_bin", type=Path, help="Input firmware .bin (ELF linker output / code only)")
    ap.add_argument("-o", "--output", type=Path, default=None, help="Output packed bin (default: <input>.packed.bin)")
    ap.add_argument("--template", type=Path, default=None, help="Optional factory BIN to copy fixed fields (sdk/date/read_cfg/etc).")
    ap.add_argument("--template-param", action="store_true", help="If template is set, copy param block from template instead of DEFAULT_PARAM.")
    ap.add_argument("--code-off", default=None, help="Override code offset (hex, e.g. 2000). Otherwise from template/INI.")
    ap.add_argument("--pad-byte", default="00", help="Padding byte before code (default: 00)")
    ap.add_argument("--calc-crc32", action="store_true", help="Fill code_crc32 in FW header (default: 0 like factory).")
    ap.add_argument("--param-offset", default=f"{DEFAULT_PARAM_OFFSET:X}", help="Param offset (hex, default: 200)")
    ap.add_argument("--param-hex", default=None, help="Override param block bytes as hex (e.g. '04 00 2B 1A')")
    args = ap.parse_args()

    script_dir = Path(__file__).resolve().parent
    ini_path = script_dir / INI_NAME

    common: dict = {}
    spi: dict = {}
    if ini_path.is_file():
        common, spi = load_ini(ini_path)

    fw_path = args.input_bin
    if not fw_path.is_file():
        raise SystemExit(f"Input bin not found: {fw_path}")

    out_path = args.output or fw_path.with_suffix(fw_path.suffix + ".packed.bin")

    pad_byte_str = args.pad_byte.strip().lower()
    if pad_byte_str.startswith("0x"):
        pad_byte_str = pad_byte_str[2:]
    pad_byte = int(pad_byte_str, 16) & 0xFF

    code = fw_path.read_bytes()

    template = None
    t = None
    if args.template is not None:
        template = args.template.read_bytes()
        t = _parse_template_headers(template)

    param_offset = parse_int(args.param_offset)
    if param_offset <= 0:
        raise SystemExit("bad --param-offset")

    if args.param_hex is not None:
        param = bytes.fromhex(args.param_hex)
    elif t is not None and args.template_param:
        # param_len берём из первых 2 байт param блока.
        code_off_tmp = t["boot"]["code_off"]
        if len(template) < param_offset + 2:
            raise SystemExit("Template too small for param")
        param_len = struct.unpack_from("<H", template, param_offset)[0]
        if param_len == 0 or param_len > (code_off_tmp - param_offset):
            raise SystemExit("Bad template param_len")
        param = template[param_offset : param_offset + param_len]
    else:
        param = DEFAULT_PARAM

    if len(param) < 2:
        raise SystemExit("param too small")
    param_len = struct.unpack_from("<H", param, 0)[0]
    if param_len != len(param):
        raise SystemExit(f"param_len mismatch: hdr={param_len} actual={len(param)}")

    param_crc16 = hgic_crc16_modbus(param)
    code_crc32 = hgic_crc32(code) if args.calc_crc32 else 0

    # code offset
    if args.code_off is not None:
        code_off = parse_int(args.code_off)
    elif t is not None:
        code_off = int(t["boot"]["code_off"])
    else:
        code_off = parse_int(spi.get("CodeAddrOffset", "2000"))
    if code_off <= 0:
        raise SystemExit("CodeAddrOffset must be > 0")

    # headers
    if t is not None:
        # копируем фиксированные поля из template
        spi_raw = t["spi_raw"]
        spi_hdr = build_spi_info_header({}, template_raw=spi_raw)

        spi_vals = {
            "Flag": f"{t['boot']['boot_flag']:X}",
            "Version": f"{t['boot']['version']:X}",
            "CodeLoadToSramAddr": f"{t['boot']['boot_to_sram_addr']:X}",
            "CodeExeAddr": f"{t['boot']['run_sram_addr']:X}",
            "PLL_SRC_MHZ": f"{t['boot']['mode'] & 0xFF:X}",
            "PLL_EN": "1" if (t['boot']['mode'] & (1<<8)) else "0",
            "DebugInfoEn": "1" if (t['boot']['mode'] & (1<<9)) else "0",
            "AesEnable": "1" if (t['boot']['mode'] & (1<<10)) else "0",
            "CodeCRC16": "1" if (t['boot']['mode'] & (1<<11)) else "0",
            # baud/strength и offset
            "SPI_CLK_MHZ": f"{t['boot']['baud_strength'] & 0x3FFF:X}",
            "DriverStrength": f"{(t['boot']['baud_strength'] >> 14) & 0x3:X}",
        }
        boot_hdr = build_boot_header(spi_vals, code, code_off)

        fw_tpl = t["fw"]
        fw_hdr = build_fw_info_header(
            {},
            code_crc32=code_crc32 if args.calc_crc32 else fw_tpl["code_crc32"],
            param_crc16=param_crc16,
            template_vals=(
                int(fw_tpl["sdk_version"]),
                int(fw_tpl["svn_version"]),
                int(fw_tpl["date"]),
                int(fw_tpl["chip_id"]),
                int(fw_tpl["cpu_id"]),
            ),
        )
    else:
        boot_hdr = build_boot_header(spi, code, code_off)
        spi_hdr = build_spi_info_header(spi)
        fw_hdr = build_fw_info_header(common, code_crc32=code_crc32, param_crc16=param_crc16)

    headers = boot_hdr + spi_hdr + fw_hdr
    if len(headers) > code_off:
        raise SystemExit(f"Headers too large ({len(headers)}) to fit before 0x{code_off:X}")

    # output: area up to code_off
    # - без template: забиваем pad_byte (обычно 0x00)
    # - с template: копируем "преамбулу" целиком (у некоторых BIN там есть доп. данные)
    if template is not None:
        if len(template) < code_off:
            raise SystemExit("Template too small for code_off")
        out = bytearray(template[:code_off])
    else:
        out = bytearray([pad_byte]) * code_off

    out[0:len(headers)] = headers
    if param_offset + len(param) > code_off:
        raise SystemExit("param overlaps code area")
    out[param_offset : param_offset + len(param)] = param
    out += code

    out_path.write_bytes(out)

    if ini_path.is_file():
        print(f"INI    : {ini_path}")
    if args.template is not None:
        print(f"Template: {args.template}")
    print(f"Input  : {fw_path} ({len(code)} bytes)")
    print(f"Offset : 0x{code_off:08X}")
    print(f"Param  : off=0x{param_offset:04X} len={len(param)} crc16=0x{param_crc16:04X}")
    print(f"CRC32  : 0x{code_crc32:08X}")
    print(f"Output : {out_path} ({len(out)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
