# QrcKit

A small, dependency-free desktop utility to **encrypt** standard LRC/TXT lyrics into QQ Music's local .qrc lyric format, and to **decrypt / convert** existing .qrc files back into readable **TXT / XML / standard LRC**.

Pure Python (standard library only), ships with a lightweight Tkinter GUI.

## Requirements

- Python 3.8+ (with Tkinter).


- - **Windows / macOS**: official Python installers include Tkinter by default.


- - **Linux**: if Tkinter is missing, install it first, e.g. sudo apt install python3-tk.

## How to launch

From the project folder, run:

```
python3 QrcKit.py
```

A small window opens. No build step, no pip install needed.

## What it does

- **Encrypt** — take one or more plaintext lyric files (.lrc / .txt) and produce a <name>.qrc that is byte-compatible with QQ Music's local encrypted lyric container.


- **Decrypt** — take one or more .qrc files and export them as:


- - lrc — auto-converted to **standard LRC** ([mm:ss.xx]line), including stripping the <QrcInfos> XML wrapper and flattening word-by-word (karaoke) timing into plain per-line timestamps;


- - txt — the raw decrypted payload as-is;


- - xml — the raw payload saved as .xml (useful when the payload is a <QrcInfos> document).


- Batch mode: select multiple files at once; choose a custom output folder (defaults to the source folder).

> Output correctness has been verified by re-encrypting known-good .qrc payloads and obtaining **byte-identical** files to the originals.

## How the local .qrc format is encrypted

> **Timeliness note:** This documents the on-disk format as observed and fully verified in **October 2026**. QQ Music may change its container, keys, or padding in future client versions; if a newer file no longer decrypts, the format below has likely been revised.

A local .qrc file is a byte stream of:

```
[11-byte magic header][encrypted payload]
```

1. ### Magic header

The first 11 bytes are a fixed constant:

```
98 25 B0 AC E3 02 83 68 E8 FC 6C
```

The payload length after this header is always a multiple of 8.

1. ### Fixed XOR layer

Strip the 11-byte header, then XOR every payload byte with a **fixed 128-byte key, applied cyclically**:

```
body[i] ^= XOR_KEY[i mod 128]
```

```
XOR_KEY (hex) =
629F5B0900C35E95239F13117ED8923FBC90BB740EC347743D90AA3F5
1D8F411849FDE951DC3C609D59FFA66F9D8F0F7A090A1D6F3C3F3D6A190A0F7F0D8F966
FA9FD509C6C31D95DE9F8411F4D8513FAA903D7447C30E74BB90BC3F92D87E11139F23955E
C300095B9F6266A1D852F76790CAD64AC34AD6CA9067F752D8A166
```

1. ### Modified Triple-DES (ECB)

The XORed bytes are processed in 8-byte blocks with a **modified DES** (Brad Conte–style bit permutation/S-boxes as used by QQ). Three DES keys are chained; although each key string is 16 bytes, **only the first 8 bytes** feed the key schedule:

| Round | Key string (16 bytes) | Effective 8 bytes |
| ----- | --------------------- | ----------------- |
| K1    | !@#)(NHLiuy*$%^&      | !@#)(NHL          |
| K2    | 123ZXC!@#)(*$%^&      | 123ZXC!@          |
| K3    | !@#)(*$%^&abcDEF      | !@#)(*$%          |

- **Decryption order:** D(K1) → E(K2) → D(K3)


- **Encryption order:** E(K3) → D(K2) → E(K1)

1. ### Compression

The final DES output is decompressed with standard **zlib** to yield the UTF-8 lyric text. On the encryption side, the zlib stream is zero-padded to a multiple of 8 bytes before DES; the extra padding is ignored on inflate.

### Decryption pipeline (file → text)

```
raw bytes
  → drop 11-byte magic header
  → XOR cyclically with XOR_KEY
  → 3DES decrypt  D(K1)→E(K2)→D(K3)   (8-byte ECB blocks)
  → zlib inflate
  → UTF-8 plaintext
```

## Notes on this kind of format conversion

- **Bilingual lyrics are split across two files.** QQ does not put original + translation in one file. Instead it uses a side-by-side pair:


- - *_qm.qrc (or similar) = original / word-by-word lyric,


- - *_qmts.qrc = line-by-line translation,


- - and the player loads both at once and aligns them by timestamp. (ts = translation; a *_qmRoma.qrc would hold romaji.)


- **Word-by-word vs line-by-line.** The original file may carry per-character timing [lineStart,lineDur]字(start,dur)字(...). The "export as LRC" option flattens this to plain [mm:ss.xx]line text.


- **Local disk cache**  **.qrc** **≠ network EQRC.** The streaming/web lyric endpoints use a different (newer) 3DES variant; the scheme above is specifically for the **local on-disk** container identified by the 98 25 B0 … magic header. Do not expect these keys to decrypt network payloads.


- **Encoding is UTF-8.** Keep your source LRC in UTF-8.

## Disclaimer

This project is provided **for educational and interoperability purposes only**, in the hope it is useful.

- It is an independent, unofficial research work and is **not affiliated with, endorsed by, or connected to** Tencent / QQ Music.


- You are solely responsible for how you use it. Do **not** circumvent DRM, access or redistribute lyrics you do not have the rights to, or violate QQ Music's Terms of Service.


- Lyrics are the copyrighted work of their respective authors, composers, publishers, and the music rightsholders. Respect those rights.


- No warranty is provided; the software is offered "as is", without guarantee of fitness for any purpose. The author(s) accept no liability for any misuse, loss of data, or damage arising from its use.

By using this software you agree to use it lawfully and at your own risk.