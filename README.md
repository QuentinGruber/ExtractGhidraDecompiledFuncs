## Usage

- In ghidra open the export program windows by pressing the "O" key
- Export in C/C++ format and be sure that the "selection only" checkbox isn't checked.

### If you have [Deno](https://deno.land)

Run in cmd `deno run -A --unstable extractGDF.ts {path to your file from ghidra}`

### If you use the .exe

Run in cmd `extractGDF.exe {path to your file from ghidra}`

### Try the examples

- `deno run -A --unstable extractGDF.ts examples/Not.A.Bug.exe.c`
- `extractGDF.exe examples/Not.A.Bug.exe.c`

## Versions

Tested with Ghidra v9.2.2 and Deno v1.8.2
