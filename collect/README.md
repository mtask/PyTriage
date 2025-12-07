## Building collect.py

```bash
pip3 install pyinstaller
pyinstaller --onefile --paths=. collect.py
```

After building ship `./dist/collect` and `config.yaml` to target machine and run collection.

```bash
sudo ./collect -c config.yaml --collect --capture -if eth0,eth1
```

Check the collection path from the last log message to stdout. For example:

```
2025-12-07 22:04:07,548 [INFO] Collection finished: /tmp/out/hostname_20251207_220252.tar.gz
```

Copy collection to analysis machine and continue with [analysis](https://github.com/mtask/PyTriage/tree/main/analyze).
