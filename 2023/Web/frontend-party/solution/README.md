
# Frontend-party -- Solution

## 1. What can we do with web page sources?

If we inspect the web page source, we can spot one script written in JavaScript.
This script looks like it is **obfuscated**.

## 2. Deobfuscation with tool

There are many available tools for the deobfuscation of JavaScript.
For example, we can use https://deobfuscate.relative.im/.

## 3. Deobfuscation

We get some code from the deobfuscator and can spot the `eval` function.
Input to the `eval` function is some `base64` encoded JS code.

If we inspect this code, we get JavaScript code again.
This JavaScript code is again obfuscated, and we repeat the same action.

We get some JavaScript code:

```
let key = 'emIxVe9nmsl61Gg7ZTW7yIsfAaZUeK5d',
  array = [
    49, 47, 29, 52, 45, 45, 13, 56, 92, 61, 43, 105, 119, 18, 41, 104, 13, 101,
    96, 127, 38, 121, 49, 32, 20, 84, 25, 97, 82, 123, 103, 25,
  ],
  show = ''
for (var i = 0; i < key.length; ++i) {
  show += String.fromCharCode(key.charCodeAt(i) ^ array[i])
}
let canvas = document.createElement('canvas')
canvas.id = 'canvas'
canvas.width = '800'
canvas.height = '800'
document.body.appendChild(canvas)
var ctx = canvas.getContext('2d')
ctx.font = '50px Georgia'
ctx.strokeText(show)

```

## 4. Get the Flag

In this code, we can easily see that flag is a product of the `xor` operation between the key and some array.
We can run the first part of this script and print out the `show` variable: **TBTL{H4V1NG_FUN_W17H_0BFU5C470R}**.
