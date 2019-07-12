## r2dwarf

integrate r2/r2frida into dwarf

### Installation

```
cd %Dwarf%/plugins/

git clone https://github.com/iGio90/r2dwarf

~~~

# make sure r2frida is installed:
r2pm -ci r2frida

# optionally enable decompiler
r2pm -ci r2dec
```

### Features

* panel with r2 console
* disasm view enriched with graph view, decompiler and xrefs and data refs