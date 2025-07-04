---
date: '2024-02-23T12:00:00Z'
draft: false
title: 'LaCTF24 - Glottem'
summary: "This reverse-engineering challenge was part of LaCTF 2024. What we faced was a flag checker script written in both python and javascript. Sounds fun right?"

categories: 
- writeups
tags: 
    - rev
author: "bhackari"
---

## Challenge description:

>\# ./glottem
> flag? lactf{no_idea}
>incorrect


The challenge presents a flag checker script written in a mixture of JavaScript and Python. The objective is to reverse engineer the obfuscated code to understand its functionality and generate the correct flag that will pass the verification.

---

## Source code:

`glottem` is the bash script that takes one single string as input to verify, locally, if it corresponds to the flag. 
The script contains all the code necessary to perform the check:  
1. The script makes use of Here Documents https://en.wikipedia.org/wiki/Here_document to generate sections of a source code file that are treated as if they were a separate file. 
These temporary files are then executed on the fly.
You can locate the start and the end of these streams by their delimiters: `1<<4201337` and `4201337`
2. Users are prompted to input a flag via `read -p "flag? " flag`.
3. The flag is than passed as parameter to a script executed by **both a python and javascript interpreter.** 
This part of the script contains the main verification logic and the code is structured to make it possible to be run by both interpreter. 
This has been acheived thanks to the clever positioning of the comment delimeters that prevent the javaScript interpreter from evaluating python code and vice versa. 
4. If both execution of the code return 1, the flag is correct and the script prints `correct`.

```python
#!/bin/sh
1<<4201337
1//1,"""
exit=process.exit;argv=process.argv.slice(1)/*
4201337
read -p "flag? " flag
node $0 "$flag" && python3 $0 "$flag" && echo correct || echo incorrect
1<<4201337
*///""";from sys import argv
e = [[[...],[...],...],...,[[...],[...],...]]
alpha="abcdefghijklmnopqrstuvwxyz_"
d=0;s=argv[1];1//1;"""
/*"""
#*/for (let i = 0; i < s.length; i ++) {/*
for i in range(6,len(s)-2):
    #*/d=(d*31+s.charCodeAt(i))%93097/*
    d+=e[i-6][alpha.index(s[i])][alpha.index(s[i+1])]#*/}
exit(+(d!=260,[d!=61343])[0])
4201337⏎ 

```

#### Reversing the algorithm

Let's focus on the second part of the script containing the js and python code.
+ A 3-dimensional matrix `e` is created containing apparently random numbers 
+ the alphabet and the letters order is saved in `alpha`
+ the user input is moved in the variable `s` and the variable `d` is set to zero.

Then, what follows are two "nested" loops that modify the value of `d` based on the characters in `s`.

>Because of the different intepreters, the 2 for loop are not really nested and their execution is copletely indipendent. 
>Their execution takes place in 2 entirely different context with 2  different instances of `d` and `s`.

If we convert the Javascript part into equivalent Python code we get the following 2 distinct loops:

```python
# first loop converted from js to python
for i in range(0, len(s)):
    d1=(d1*31+ord(s[i]))%93097

# second loop already in python
for i in range(6,len(s)-2):
    d2+=e[i-6][alpha.index(s[i])][alpha.index(s[i+1])]#*/}
```

1. The first loop generates a hash based on the input string.
It iterates through each character of the string using a for loop. For each character, its ascii value is obtained using the `ord()` function. This value is then added to the current value of the hash multiplied by 31. This step effectively accumulates the contribution of each character to the overall hash value.
To prevent the hash value from growing excessively large and to maintain consistency in the range of hash values, a modulo operation is performed after each update. This operation ensures that the hash value remains within a predefined range, specified by the modulus `93097`.
**The flag hash has to be equal to 61343.**

1. The second loop iterates through a subset of characters in s starting from index 6 and ending two characters before the end of the string (skipping `lactf{`  and  `}` ) .
Within the loop, d is updated by accessing elements of e using indices derived from character pairs in s. The character at index i and its succeeding character at index `i+1` are mapped to their positions in the alphabet using `alpha.index()` to determine the indices for accessing e.
The retrieved values from e are then added to d, accumulating the contributions of the selected character pairs to the hash value.
The algorithm concludes after iterating through the specified character range, resulting in the final hash value stored in d.
**Such value has to be equal to 260** in order for the flag to be valid. 
---

## Solution:

Understanding the 2 hash algorithms helps us find weak points that could lead us to quickly recover the flag.

In particular it is possible to notice that the array `e` exclusively contains numbers ranging from **10 to 17**. 
Furthermore, considering that the second hash value must be **260** and the flag needs to be **26** characters long, it becomes apparent that the value **260** can be produced by the second loop only if each summed value is precisely equal to **10**.


This reduces our pool of possible strings by a lot because now we know that each time we access `e` in the second loop the only right value to extract from the array and sum is 10.

We can now produce a solver based on a recursive function that produces all the possible flags that adhere to the conditions set by the second hash algorithms and the length of the flag in a feasible amount of time.
Starting from each letter of the alphabet we can recursevly append a new letter only if that letter indexes a number equal to **10** in the array e. A new recursive branch is invoked for each letter that respect that rule.

```python
valid_sequences = []

def recursive_solver(curr_letter, curr_index, sequence=[]):
    global valid_sequences

    # if we reached the 26th recursion depth level we have found a possible flag
    if curr_index == 26:
        valid_sequences = valid_sequences + [sequence+[curr_letter]]
        return
    
    # otherwise keep recursing for each letter that produces a 10
    for guess in alpha:
        number = e[curr_index][alpha.index(curr_letter)][alpha.index(guess)]
        if number == 10:
            recursive_solver(guess, curr_index+1, sequence + [curr_letter])

alpha="abcdefghijklmnopqrstuvwxyz_"
for starting_letter in alpha:
    recursive_solver(starting_letter, 0)
```


Obviously this is not enough, the hash **260** turns out to be compatible with a total of __42436__ possible flags.
To find the right one we can use the other hashing algorithm. We can test the original code against each one of our possible flag in a feasible amount of time. 
Hopefully only one of the them will produce a hash value that is equal to **61343**.


```python
for sequence in valid_sequences:
    sequence = "lactf{"+''.join(sequence)+"}"
    d = 0
    for i in range(0, len(sequence)):
        d=(d*31+ord(sequence[i]))%93097
    if d == 61343:
        print("lactf{" +sequence+  "}")
```

The output of the script is indeed a single string representing our flag.

---

## Flag:

#### `lactf{solve_one_get_two_deal}`
