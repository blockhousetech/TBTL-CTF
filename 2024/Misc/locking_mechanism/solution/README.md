# Locking Mechanism &mdash; Solution

## Source code

We have the Rust project, and there we have the `main.rs` file.

### `create_thread`

The first thing that we can see is the `create_thread` function.
Arguments to this function are the `input` of type `Vec`of `usize`, `output` of `usize` type,
`code` of type `u8`,
`locks` of `Vec` of `Mutex` and `key` of `2D` vector of `u8`.

Let us see what is happening there:

```
println!("Unlocking... {}", code);
let mut input_cond = vec![];

for i in &input {
    let input_lock = locks[*i].clone();
    let input_data = input_lock.lock().unwrap();
    input_cond.push(*input_data);
}

let output_lock = locks[output].clone();
let mut output_data = output_lock.lock().unwrap();
*output_data = true;

for cond in input_cond {
    while !cond {
        thread::sleep(Duration::from_millis(1000));
    }
}

let mut key = key.lock().unwrap();
let index = (code % 9) as usize;
key[index].push((code / 9).try_into().unwrap());
println!("Unlock done {}", code);
```

First, we print `Unlocking...` with `code.`
Then, we go through `input` and get `Mutex` from the vector at index `i`.
When we lock `Mutex`, we read-protected data (`bool`). We can spot `for` and `while` loops
where we are waiting for `bool` to be `true`. **An important thing to notice here is that `cond`
variable will not change, and if `cond` is `false`, the thread will get stuck in the `while` loop**.

Before we get to the loops, the thread will lock `output` `Mutex` and set its value to `true`.
In the end, we will push `code / 9` on index `code % 9` in the `key` vector.

The conclusion of this part is that the function will read `booleans` from the `input`, and all must be `true` if we want the thread to finish. The thread will set `true` for index `output`.

Ultimately, we print out `Unlock done` with `code`.

### `main`

In the main function, we define some vectors.
The user will enter an order in which threads will be run.
We have `key_config` vector that defines all threads that will be created.
In the end, we have `flag`, where the actual flag is encrypted with a one-time pad (xor).

The conclusion of this part is that all threads must finish, and the application will print out the decrypted flag.

### `key_config`

The `key_config` vector plays a central role. Here are the defined parameters for the threads. Input
is the first element in the tuple, and output is the second element.

## Solution

If we isolate one thread, we can see that all booleans in the input must be `true`, and the thread will set
`boolean` on index `output` to `true`. Here, we have some dependencies. The thread must start after all input threads.

If we write down all dependencies, we get a DAG (Directed Acyclic Graph). To see in which order to start threads, we will use `key_config` as input in **Topological sorting** (https://en.wikipedia.org/wiki/Topological_sorting).

There are multiple solutions, but one solution that we can get from the algorithm is:
```
82,103,45,37,56,2,9,72,13,25,64,44,21,15,23,16,59,51,39,100,65,52,28,29,99,30,24,80,49,96,42,77,95,18,20,89,81,98,101,97,63,68,58,32,90,67,78,88,26,10,33,40,85,5,57,27,75,12,87,54,43,61,92,73,22,60,93,79,55,76,6,11,91,1,41,4,47,62,38,53,94,19,36,71,66,35,50,102,14,70,69,7,31,86,0,3,48,74,34,46,17,84,83,8

```
And we got the flag: `TBTL{Unl0ck1nG_l0cK_w1tH_tHr34dS_cAn_b3_t0p_w0rK}`
