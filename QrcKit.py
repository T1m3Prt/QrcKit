# -*- coding: utf-8 -*-
"""
LRC / TXT 明文  ->  <原名>.qrc
    明文(UTF-8) -> zlib 压缩 -> 补零到8字节倍数
      -> 魔改 Triple-DES(ECB): E(K3)->D(K2)->E(K1)
      -> 与128字节固定 XOR_KEY 循环异或 -> 前置11字节魔数头

.qrc  ->  txt / xml / 标准LRC
    剥11字节头 -> XOR -> D(K1)->E(K2)->D(K3) -> zlib解压
      -> 按所选格式导出
update：2026/10/06
"""

import os
import re
import zlib


MAGIC = bytes.fromhex("9825B0ACE3028368E8FC6C")
XOR_KEY = bytes.fromhex(
    "629F5B0900C35E95239F13117ED8923FBC90BB740EC347743D90AA3F5"
    "1D8F411849FDE951DC3C609D59FFA66F9D8F0F7A090A1D6F3C3F3D6A190A0F7F0D8F966"
    "FA9FD509C6C31D95DE9F8411F4D8513FAA903D7447C30E74BB90BC3F92D87E11139F23955E"
    "C300095B9F6266A1D852F76790CAD64AC34AD6CA9067F752D8A166"
)

SB = [
[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,15,12,0,1,10,6,9,11,5,0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,10,13,8,9,4,5,11,12,7,2,14],
[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
]
SHIFT = (1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1)
PC_C = (56,48,40,32,24,16,8,0,57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35)
PC_D = (62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,60,52,44,36,28,20,12,4,27,19,11,3)
PC2 = (13,16,10,23,0,4,2,27,14,5,20,9,22,18,11,3,25,7,15,6,26,19,12,1,40,51,30,36,46,54,29,39,50,44,32,47,43,48,38,55,33,52,45,41,49,35,28,31)

def _bit_a(a,b,c):
    byteidx = b//32*4 + 3 - (b%32)//8
    bit = (a[byteidx] >> (7-(b%8))) & 1
    return bit << c

def _bit_intr(a,b,c):
    return ((a >> (31-b)) & 1) << c

def _bit_intl(a,b,c):
    return ((a << b) & 0x80000000) >> c

def _sboxbit(a):
    return (a & 0x20) | ((a & 0x1f) >> 1) | ((a & 1) << 4)

def ip(inp):
    s0=0; s1=0
    for b,sh in [(57,31),(49,30),(41,29),(33,28),(25,27),(17,26),(9,25),(1,24),(59,23),(51,22),(43,21),(35,20),(27,19),(19,18),(11,17),(3,16),(61,15),(53,14),(45,13),(37,12),(29,11),(21,10),(13,9),(5,8),(63,7),(55,6),(47,5),(39,4),(31,3),(23,2),(15,1),(7,0)]:
        s0 |= _bit_a(inp,b,sh)
    for b,sh in [(56,31),(48,30),(40,29),(32,28),(24,27),(16,26),(8,25),(0,24),(58,23),(50,22),(42,21),(34,20),(26,19),(18,18),(10,17),(2,16),(60,15),(52,14),(44,13),(36,12),(28,11),(20,10),(12,9),(4,8),(62,7),(54,6),(46,5),(38,4),(30,3),(22,2),(14,1),(6,0)]:
        s1 |= _bit_a(inp,b,sh)
    return s0,s1

def invip(s0,s1):
    out=[0]*8
    out[3] = _bit_intr(s1,7,7)|_bit_intr(s0,7,6)|_bit_intr(s1,15,5)|_bit_intr(s0,15,4)|_bit_intr(s1,23,3)|_bit_intr(s0,23,2)|_bit_intr(s1,31,1)|_bit_intr(s0,31,0)
    out[2] = _bit_intr(s1,6,7)|_bit_intr(s0,6,6)|_bit_intr(s1,14,5)|_bit_intr(s0,14,4)|_bit_intr(s1,22,3)|_bit_intr(s0,22,2)|_bit_intr(s1,30,1)|_bit_intr(s0,30,0)
    out[1] = _bit_intr(s1,5,7)|_bit_intr(s0,5,6)|_bit_intr(s1,13,5)|_bit_intr(s0,13,4)|_bit_intr(s1,21,3)|_bit_intr(s0,21,2)|_bit_intr(s1,29,1)|_bit_intr(s0,29,0)
    out[0] = _bit_intr(s1,4,7)|_bit_intr(s0,4,6)|_bit_intr(s1,12,5)|_bit_intr(s0,12,4)|_bit_intr(s1,20,3)|_bit_intr(s0,20,2)|_bit_intr(s1,28,1)|_bit_intr(s0,28,0)
    out[7] = _bit_intr(s1,3,7)|_bit_intr(s0,3,6)|_bit_intr(s1,11,5)|_bit_intr(s0,11,4)|_bit_intr(s1,19,3)|_bit_intr(s0,19,2)|_bit_intr(s1,27,1)|_bit_intr(s0,27,0)
    out[6] = _bit_intr(s1,2,7)|_bit_intr(s0,2,6)|_bit_intr(s1,10,5)|_bit_intr(s0,10,4)|_bit_intr(s1,18,3)|_bit_intr(s0,18,2)|_bit_intr(s1,26,1)|_bit_intr(s0,26,0)
    out[5] = _bit_intr(s1,1,7)|_bit_intr(s0,1,6)|_bit_intr(s1,9,5)|_bit_intr(s0,9,4)|_bit_intr(s1,17,3)|_bit_intr(s0,17,2)|_bit_intr(s1,25,1)|_bit_intr(s0,25,0)
    out[4] = _bit_intr(s1,0,7)|_bit_intr(s0,0,6)|_bit_intr(s1,8,5)|_bit_intr(s0,8,4)|_bit_intr(s1,16,3)|_bit_intr(s0,16,2)|_bit_intr(s1,24,1)|_bit_intr(s0,24,0)
    return bytes(out)

def f(state,key):
    t1 = _bit_intl(state,31,0)|((state & 0xf0000000)>>1)|_bit_intl(state,4,5)|_bit_intl(state,3,6)|((state & 0x0f000000)>>3)|_bit_intl(state,8,11)|_bit_intl(state,7,12)|((state & 0x00f00000)>>5)|_bit_intl(state,12,17)|_bit_intl(state,11,18)|((state & 0x000f0000)>>7)|_bit_intl(state,16,23)
    t2 = _bit_intl(state,15,0)|((state & 0x0000f000)<<15)|_bit_intl(state,20,5)|_bit_intl(state,19,6)|((state & 0x00000f00)<<13)|_bit_intl(state,24,11)|_bit_intl(state,23,12)|((state & 0x000000f0)<<11)|_bit_intl(state,28,17)|_bit_intl(state,27,18)|((state & 0x0000000f)<<9)|_bit_intl(state,0,23)
    lr=[(t1>>24)&255,(t1>>16)&255,(t1>>8)&255,(t2>>24)&255,(t2>>16)&255,(t2>>8)&255]
    for i in range(6): lr[i]^=key[i]
    s = (SB[0][_sboxbit(lr[0]>>2)]<<28)|(SB[1][_sboxbit(((lr[0]&3)<<4)|(lr[1]>>4))]<<24)|(SB[2][_sboxbit(((lr[1]&15)<<2)|(lr[2]>>6))]<<20)|(SB[3][_sboxbit(lr[2]&63)]<<16)|(SB[4][_sboxbit(lr[3]>>2)]<<12)|(SB[5][_sboxbit(((lr[3]&3)<<4)|(lr[4]>>4))]<<8)|(SB[6][_sboxbit(((lr[4]&15)<<2)|(lr[5]>>6))]<<4)|SB[7][_sboxbit(lr[5]&63)]
    pbits=[15,6,19,20,28,11,27,16,0,14,22,25,4,17,30,9,1,7,23,13,31,26,2,8,18,12,29,5,21,10,3,24]
    out=0
    for i,b in enumerate(pbits):
        out |= _bit_intl(s,b,i)
    return out

def key_setup(key, decrypt):
    C=0;D=0
    for i in range(28):
        C |= _bit_a(key, PC_C[i], 31-i)
        D |= _bit_a(key, PC_D[i], 31-i)
    sched=[[0]*6 for _ in range(16)]
    for i in range(16):
        C = ((C<<SHIFT[i])|(C>>(28-SHIFT[i]))) & 0xfffffff0
        D = ((D<<SHIFT[i])|(D>>(28-SHIFT[i]))) & 0xfffffff0
        tg = 15-i if decrypt else i
        for j in range(24):
            sched[tg][j//8] |= _bit_intr(C, PC2[j], 7-(j%8))
        for j in range(24,48):
            sched[tg][j//8] |= _bit_intr(D, PC2[j]-27, 7-(j%8))
    return sched

def crypt_block(inp, sched):
    s0,s1=ip(inp)
    for idx in range(15):
        t=s1; s1=f(s1,sched[idx])^s0; s0=t
    s0=f(s1,sched[15])^s0
    return invip(s0,s1)

K1=b"!@#)(NHLiuy*$%^&"
K2=b"123ZXC!@#)(*$%^&"
K3=b"!@#)(*$%^&abcDEF"
# 加密 schedule: E(K3)->D(K2)->E(K1)
_e3 = key_setup(K3, False); _e2 = key_setup(K2, True); _e1 = key_setup(K1, False)
# 解密 schedule: D(K1)->E(K2)->D(K3)
_s1 = key_setup(K1, True);  _s2 = key_setup(K2, False); _s3 = key_setup(K3, True)

def _des(data, scheds):
    out=bytearray()
    for i in range(0,len(data),8):
        b=data[i:i+8]
        for s in scheds: b=crypt_block(b,s)
        out+=b
    return bytes(out)

def _xor_cycle(body):
    body=bytearray(body); k=len(XOR_KEY)
    for i in range(len(body)):
        body[i] ^= XOR_KEY[i - (i//k)*k]
    return bytes(body)

def lrc_text_to_qrc_bytes(text):
    """明文 LRC/TXT 字符串 -> .qrc 二进制。"""
    comp = zlib.compress(text.encode('utf-8'))
    r = len(comp) % 8
    if r: comp = comp + bytes(8 - r)
    return MAGIC + _xor_cycle(_des(comp, [_e3,_e2,_e1]))

def qrc_bytes_to_text(data):
    """.qrc 二进制 -> 明文字符串。"""
    if bytes(data[:11]) != MAGIC:
        raise ValueError("不是当前支持的 QQMusic .qrc 文件：魔数头不匹配")
    raw = _xor_cycle(bytes(data[11:]))
    return zlib.decompress(_des(raw, [_s1,_s2,_s3])).decode('utf-8')

def _ms_to_lrc_tag(ms):
    ms = int(ms)
    mm = ms // 60000
    rem = ms % 60000
    ss = rem // 1000
    cs = (rem % 1000) // 10
    return "[%02d:%02d.%02d]" % (mm, ss, cs)

def qrc_plaintext_to_standard_lrc(text):
    """解密后的明文（可能是 QrcInfos XML 或裸 LRC）转成标准 LRC 文本。"""
    # 1) 若为 XML，抽出 LyricContent 内层歌词
    m = re.search(r'LyricContent="(.*)"\s*/>', text, re.DOTALL)
    body = m.group(1) if m else text

    out_lines = []
    for line in body.splitlines():
        line = line.rstrip()
        if not line.strip():
            continue
        # 已是标准时间戳 LRC 行 [mm:ss.xx]... 或标签 [ti:] 等 -> 原样保留
        if re.match(r'^\[\d\d:\d\d\.\d\d\]', line) or re.match(r'^\[(ti|ar|al|by|offset|re|ve|length):', line, re.I):
            out_lines.append(line)
            continue
        # QRC 逐字行：[行起始ms,行时长ms]字(起,时长)字(...)
        mm = re.match(r'^\[(\d+),(\d+)\](.*)$', line)
        if mm:
            start_ms = mm.group(1)
            rest = mm.group(3)
            plain = re.sub(r'\(\d+,\d+\)', '', rest)   # 去掉逐字时间标注
            out_lines.append(_ms_to_lrc_tag(start_ms) + plain)
            continue
        out_lines.append(line)  # 兜底
    return "\n".join(out_lines) + "\n"

def main():
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    root = tk.Tk()

    state = {"files": [], "outdir": "", "mode": tk.StringVar(value="enc"),
             "dec_fmt": tk.StringVar(value="lrc")}


    root.title("QRC 歌词加/解密工具")
    root.geometry("680x480")

    tk.Label(root, text="QQ音乐 .qrc 歌词 加解密工具", font=("Arial", 14, "bold")).pack(pady=8)

    # 操作模式
    mode_frame = tk.LabelFrame(root, text="操作")
    mode_frame.pack(fill="x", padx=10, pady=4)
    tk.Radiobutton(mode_frame, text="加密：LRC/TXT  ->  .qrc", variable=state["mode"],
                   value="enc", command=lambda: fmt_combo.config(state="disabled")).pack(side="left", padx=8)
    tk.Radiobutton(mode_frame, text="解密：.qrc  ->  文本", variable=state["mode"],
                   value="dec", command=lambda: fmt_combo.config(state="readonly")).pack(side="left", padx=8)
    tk.Label(mode_frame, text="解密输出格式：").pack(side="left", padx=(16,2))
    fmt_combo = ttk.Combobox(mode_frame, width=8, state="disabled", textvariable=state["dec_fmt"],
                             values=["lrc", "txt", "xml"])
    fmt_combo.pack(side="left")

    # 按钮行
    btn_frame = tk.Frame(root)
    btn_frame.pack(fill="x", padx=10, pady=6)

    def pick_files():
        if state["mode"].get() == "enc":
            ftypes = [("LRC / 文本歌词", "*.lrc *.txt"), ("所有文件", "*.*")]
            title = "选择要加密的 LRC/TXT 文件"
        else:
            ftypes = [("QRC 歌词", "*.qrc"), ("所有文件", "*.*")]
            title = "选择要解密的 .qrc 文件"
        fs = filedialog.askopenfilenames(title=title, filetypes=ftypes)
        if fs:
            state["files"] = list(fs)
            listbox.delete(0, tk.END)
            for f in fs: listbox.insert(tk.END, os.path.basename(f))
            log(f"已选择 {len(fs)} 个文件")

    def pick_outdir():
        d = filedialog.askdirectory(title="选择输出文件夹")
        if d:
            state["outdir"] = d
            log(f"输出目录：{d}")

    def convert():
        if not state["files"]:
            messagebox.showwarning("提示", "请先选择文件"); return
        is_enc = state["mode"].get() == "enc"
        ok = 0
        for path in state["files"]:
            try:
                base = os.path.splitext(os.path.basename(path))[0]
                outdir = state["outdir"] or os.path.dirname(path)
                if is_enc:
                    text = open(path, "r", encoding="utf-8").read()
                    data = lrc_text_to_qrc_bytes(text)
                    outpath = os.path.join(outdir, base + ".qrc")
                    open(outpath, "wb").write(data)
                    log(f"OK  {os.path.basename(path)} -> {base}.qrc ({len(data)} 字节)")
                else:
                    data = open(path, "rb").read()
                    plain = qrc_bytes_to_text(data)
                    fmt = state["dec_fmt"].get()
                    if fmt == "lrc":
                        content = qrc_plaintext_to_standard_lrc(plain); ext = "lrc"
                    elif fmt == "xml":
                        content = plain; ext = "xml"
                    else:  # txt
                        content = plain; ext = "txt"
                    outpath = os.path.join(outdir, base + "." + ext)
                    open(outpath, "w", encoding="utf-8").write(content)
                    log(f"OK  {os.path.basename(path)} -> {base}.{ext}")
                ok += 1
            except Exception as e:
                log(f"FAIL {os.path.basename(path)} : {e}")
        log(f"完成：成功 {ok}/{len(state['files'])}")
        messagebox.showinfo("完成", f"成功 {ok}/{len(state['files'])} 个文件")

    tk.Button(btn_frame, text="① 选择文件", width=14, command=pick_files).pack(side="left", padx=4)
    tk.Button(btn_frame, text="② 输出文件夹", width=14, command=pick_outdir).pack(side="left", padx=4)
    tk.Button(btn_frame, text="③ 开始", width=12, bg="#4a9", fg="white", command=convert).pack(side="left", padx=4)

    listbox = tk.Listbox(root, height=7)
    listbox.pack(fill="both", expand=True, padx=10, pady=4)

    logbox = tk.Text(root, height=9, bg="#222", fg="#0f0")
    logbox.pack(fill="both", expand=True, padx=10, pady=(0, 8))

    def log(msg):
        logbox.insert(tk.END, msg + "\n"); logbox.see(tk.END)

    log("就绪。加密：选 LRC/TXT；解密：选 .qrc 并在右上选择输出格式(lrc/txt/xml)。")
    root.mainloop()

if __name__ == "__main__":
    main()
