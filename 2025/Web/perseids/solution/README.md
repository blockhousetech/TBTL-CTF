# Perseids &mdash; Solution

## Summary

We can see the WebAssembly wrapper is loaded and `generate_seed` is called:

```javascript
import init, { generate_seed } from "/static/perseids.js";
await init();
```

The WASM module and its exports are available in the browser, so we can interact with the module from DevTools.

## Attack

We can read the WASM linear memory from the browser console:

```javascript
var mod  = await import('/static/perseids.js');
var wasm = await mod.default();

mod.generate_seed();

var mem = new Uint8Array(mod.memory.buffer);
```

Calling `generate_seed()` causes the module to write data into its linear memory. The flag may be present only at certain points during execution, so the strategy is:

* Manually invoke `generate_seed()` (or re-invoke it if the page already did).
* Use the debugger or breakpoints to pause execution right after the memory write (if the flag is transient).
* Dump the linear memory and scan it for the flag format.

Example memory-scan code:

```javascript
var mem = new Uint8Array(mod.memory.buffer);

// Scan as ASCII
var text = new TextDecoder().decode(mem);

// Search for flag
console.log(text.match(/FortID\{[^}]+\}/));
```

This process reliably extracts the flag by locating the `FortID{...}` pattern in the WASM memory at the right moment.

If you place a breakpoint at the location where the flag is written (in the original analysis a useful offset was `0000DA17`) and then run the scan while paused, the flag appears:

`FortID{w38_4nd_81n4ry_4r3_900d_c0up13_4nd_y0u_c4n_d0_50m3_c001_4nd_57r4n93_57uff}`

