
## Modules

### Patterns and YARA modules

* Load your patterns in text files containing things like IoCs under `patterns` directory. Files should have `.txt` extension.
* Load your YARA rules under `yara` directory. Files should have `.yar` extension.

Both directories can have sub-directories. Files (`.yar`/`.txt`) are searched recursively under those directories if related modules are enabled.

Directory paths for patterns and rules can be changed in `config.yaml`:

```
modules:
  pattern:
    # Pattern txt files are here. One pattern per line
    # Can contain sub directories
    # Expects .txt extension
    patterns_dir: ./patterns
  yara:
    # Yara yar files are here
    # Can contain sub directories
    # Expects .yar extension
    rules_dir: ./yara
```

Enable YARA module by giving `--yara` option and patterns module by giving `--pattern` option.

### Other analysis

Other analysis is enabled by giving `--analysis` option.

## Report

TBD
