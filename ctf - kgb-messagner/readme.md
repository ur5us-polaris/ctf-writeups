# KGB Messanger Writeup
## Setting
* KGB Messanger is an Android ctf, themed after "Archer" TV show.
* Players are given an apk and a series of three challenges to overcome, each with stated difficulty and a hint.
* The CTF is available at https://github.com/tlamb96/kgb_messenger

---
## Alerts (Medium)
> Hint: The app keeps giving us these pesky alerts when we start the app. We should investigate.
* We started by setting up an emulated device, using Android Studio. The emulated device was based on Pixel XL, running Android 8.1 (APK 27).
* After boot, we installed the apk without any notable events:
</br>![icon](images/Pasted%20image%2020211203132930.png)
* After installation, we launched the application by clicking the app icon. We were greeted with this error, followed by the application quitting:
</br>![Alt_Text](images/Pasted%20image%2020211203133049.png)
* Suspecting the application runs some sort of checks at start up, we disassembled the apk using dex2jar, oponed the jar file using jd-gui and looked for relevant code at MainActivity.
* Right at onCreate method we were able to identify view code lines that were likely associated with the checking at hand:
</br>![Alt_Text](images/Pasted%20image%2020211203133659.png)
It seems that the checking includes the following steps:
1. Get "user.home" system property 
2. If the property doesn't exist, is empty or not "Russia", display an error message and quit
3. If the property is "Russia", continue with the method
* To bypass this challenge, we wrote a frida script that hooks to System.getProperty method, and returns "Russia" if the method is called with argument "user.home":
	```JavaScript
	'use strict' // Code will be executed in strict mode, i.e avoid using undefined variables
	if (Java.available) { // Execute only if Java runtime is available
		Java.perform(function() { // Verify current thread is attached to Java VM
			try {
				var cls = Java.use('java.lang.System');
				cls.getProperty.overload("java.lang.String").implementation = function(prop) {
					console.log("[+] getProperty call to: " + prop.toString());
					if (prop.toString() == "user.home") {
						console.log("[+] property is user.home, returning 'Russia'");
						return "Russia";
					}
					else {
						return this.getProperty(prop);
					}
				};
			}
			catch(error) {
				console.log("[-] An exception has occured");
				console.log(String(error.stack));
			}

		});
	}
	else {
	console.log("[-] ERROR: Java is not available.");
	}
	```
* We launched the app using frida, while loading the script we wrote. The bypass was successful:
</br>![Alt_Text](images/Pasted%20image%2020211203135345.png)
* But now we fail a second check:
</br>![Alt_Text](images/Pasted%20image%2020211203135431.png)
* This time, the string we need to match is not showing plain in the code:
</br>![Alt_Text](images/Pasted%20image%2020211203162109.png)
* To overcome it, we will hook the getString method and print out the string that returns in every call:
	```JavaScript
	var resources = Java.use ('android.content.res.Resources');
	resources.getString.overload("int").implementation = function(id) {
		var str = this.getString(id);
		console.log("ID: " + id + " = " + str);
		return str;
	};
	```
* We will add the following function to our frida script and launch the app using frida. The hook works, we get a base64 encoded string, that after decoding revelas the  first flag:
</br>![Alt_Text](images/Pasted%20image%2020211203161041.png)
```bash
base64 -d 'RkxBR3s1N0VSTDFOR180UkNIM1J9Cg=='
FLAG{57ERL1NG_4RCH3R}
```
	

* Now all we need is to hook the getenv function and return "RkxBR3s1N0VSTDFOR180UkNIM1J9Cg== " when the method is called with the argument USER:
	```JavaScript
	cls.getenv.overload("java.lang.String").implementation = function(env) {
	console.log("[+] getenv call to: " + env.toString());
	if (env.toString() == "USER") {
		console.log("[+] env variable is USER, returning 'RkxBR3s1N0VSTDFOR180UkNIM1J9Cg=='");
		return "RkxBR3s1N0VSTDFOR180UkNIM1J9Cg==";
	}
	else {
		return this.getenv(env);
	}
	```
* Again we launch the app with frida, and finally we get to the login screen:
</br>![Alt_Text](images/Pasted%20image%2020211203162628.png)

---
## Login (Easy)
> Hint: This is a recon challenge. All characters in the password are lowercase.

* A short look at the decompiled LoginActivity class in jd-gui reveals the login flow:
	1. Get username and password from the EditText elements
	2. Check if given username is equal to a string stored in resources. If the check fails, display the message "User not recognized".
	3. Perform MD5 on the given password, convert it to a hex string and check if it is equal to a string stored in resources. If the check fails, diaply the message "Incorrect password".
	4. If the username and password match, build the flag with some xor operations on the username and password and display it as a message.
* At first glance, you'd think we can solve this challenge in a similar manner we solved the previous one:hook getString to get the username and hook the password-checking password and alter it to always return true. The problem is that the flag is derived from the password, so even though entering the wrong one will allow us to proceed to the next activity, we still won't get the right flag.
* Considering the challenge's hint, we need to approach this challenge with recon. It is plausble that important strings and kept in the same resources file. In that in mind, we will return to the decompiled apk and perform a search in the res folder after a file containing the resource we used in the last part of the challenge: " RkxBR3s1N0VSTDFOR180UkNIM1J9Cg== ".
* We used sublime text's build in search feature, and found the string inside values\strings.xml:
</br>![Alt_Text](images/Pasted%20image%2020211203170521.png)
* At the bottom of the file we found some intersting strings that might just be what we are looking for:
</br>![Alt_Text](images/Pasted%20image%2020211203170758.png)
* the username can be used right away, but the password is not in plain text. However, considering the password checking flow in LoginActivity, we can assume that the password we found is stored after being hashed with MD5 and converted to hex chars.
* MD5 hashes can useully be cracked using a dictionary, or even by utilizing websites that specialise in hash cracking, such as https://crackstation.net/. The problem is that the hash we found has 30 characters, while MD5 hashes are 32 characters long.
* After closer examination of the password checking method in LoginActivity, we noticed that the  password hash is broken into bytes, and each byte is encoded in hex and than concatinated to the final password string. The process of converting the byte into hex is done using "%x" formatter, which cuts the string representation of the hex into minimum. For example, 31 will be converted to "1e", but 10 will be converted to "a", and not "0a". This means that we have 2 missing "0"s in the hash, and we must place them correctly in order to be able to crack  it.
* We couldn't find any indication for the right position of the "0"s, so we created a python script that creates every possible permutation:
	```python
	STR = '84e343a0486ff05530df6c705c8bb4'
	CHAR = '0'
	def insert_in_index(str, char, index):
		return str[:index] + char + str[index:]
	
	for i in range(len(STR) + 2):
		temp_str = insert_in_index(STR, CHAR, i)
	for j in range(i+1, len(STR) + 2):
		print(insert_in_index(temp_str, CHAR, j))
	```
* After running the script, we were holding 496 different permutations:
</br>![Alt_Text](images/Pasted%20image%2020211203230826.png)
* The next step was trying to crack each permutation. We could use john the ripper or hashcat, but chose to use https://crackstation.net/, which holds a massive dictionary and allows running it against 20 hashes in each run. After a second or so we got a crack:
</br>![Alt_Text](images/Pasted%20image%2020211203231040.png)
* We now hold the username and password, all that is left is to use them to login and recieve the next flag:
</br>![Alt_Text](images/Pasted%20image%2020211203231321.png)

---
## Social Engineering (Hard)
> Hint: It looks like someone is bad at keeping secrets. They're probably susceptible to social engineering... what should I say?
* After logging in, we recieve a messanger-like screen, showing previous messages between several agents.
* From the conversation it seems that Boris had an accident where he gave the password to an unauthorized person, just because that person asked him:
</br>![Alt_Text](images/Pasted%20image%2020211204145508.png)
* From the hint we unserstand we should use social engineering technique in this challenge, so Boris seems like the right target for it.
* After fooling around with some trial-and-error messages it became clear that a specific string should be sent, in order to trigger an answer from Boris, so we went back to the disassembled code.
* The code revealed that each message we send is sent to 2 methods, where some nasty operations are performed on them, and the product is compared against hard-coded strings:
</br>![Alt_Text](images/Pasted%20image%2020211204150303.png)
* We started by analyzing method a: from the source, it became clear that method a performs the following actions on the message sent by us:
		1. Xor each element in the first half of the string with 0x41
		2. Xor each element in the second half of the string with 0x32
		3. Reverse the string
	The product of the method is compared against ```V@]EAASB\022WZF\022e,a$7(&am2(3.\003```, where \0xx is xx in octat base.
	So in order to get the expected message, all we need to do is to reverse the process:
		1. Xor each element in the first half of the string with 0x32
		2. Xor each element in the first half of the string with 0x41
		3. Reverse the string
	We wrote a short python script that performs the above:
	```python
	from math import floor  
  
	encoded = "V@]EAASB\x12WZF\x12e,a$7(&am2(3.\x03"  
	decoded = ""  
	for char in encoded[:floor(len(encoded)/2)]:  
    	decoded += chr((ord(char) ^ 0x32))  
	for char in encoded[floor(len(encoded)/2):]:  
    	decoded += chr((ord(char) ^ 0x41))  
	print(decoded[::-1])
	```
	
   And got the plain:
	</br>![Alt_Text](images/Pasted%20image%2020211204155907.png)
	Well, sort of. The '$' seems to be misplaced, but we can assume the word should be "me", and indedd, sending the message "Boris, give me the password" triggered Boris to answer:
</br>![Alt_Text](images/Pasted%20image%2020211204160119.png)
* Moving on to Method b: at first the method seemed to be very complicated, but in second glance, it became clear that the disassembler complicated matters unnecessarily. After some clean-up, we ended up with a much simpler method:
	```Java
	private static String b(String paramString) {
		char[] arrayOfChar = paramString.toCharArray();
		System.out.println("Starting String: " + new String(arrayOfChar));
		// Do some nasty modulation and bitshift on each char in the string
		for (char c1 = Character.MIN_VALUE; c1 < arrayOfChar.length; c1++)
		{
			arrayOfChar[c1] = (char)(char)(arrayOfChar[c1] >> c1 % 8 ^ arrayOfChar[c1]);
		}
		System.out.println("String is now: " + new String(arrayOfChar));

		// Reverse the string
		for (byte b2 = 0; b2 < arrayOfChar.length / 2; b2++)
		{
			char b1 = arrayOfChar[b2];
			arrayOfChar[b2] = (char)arrayOfChar[arrayOfChar.length - b2 - 1];
			arrayOfChar[arrayOfChar.length - b2 - 1] = (char)b1;
		}
	```
	In short, the method performs the following actions on the message sent by us:
	1. For each character at index i, right bitshift i times, and xor against original character
	2. Reverse the string
	The product of the method is compared against ```\000dslp}oQ\000 dks$|M\000h +AYQg\000P*!M$gQ\000"```, where \0xx is xx in octat base.
* Bitshifting is not a loseless operation, so just reversing the process will not necessarily repreduce the plain text. Instead, we decided to enumerate possible characters that after going through the above process, may produce a coherent sentence. We operated under the following assumptiona:
	1. The expected message will be a string containing common characters: A-Z, a-z, 0-9, and some special characters: !, * , ?, comma and period.
	2. As a follow up to Boris' response, the expected message should be "polite". i.e, it will contain "please" and more polite ways of asking a password, rather than saying "give me".
	3. Every character can preduce \000, so we will skip the enumration for \000 and hope we get a coherente enough sentance to gap the holes.
* The following script reversed the encoded string and displayed possible charcter for each element in the string:
	```python
	def get_possible_chars(index, target_char):  
		target_char = ord(target_char)  
		if target_char == 0:  
			print('?', end='', flush=True)  
			return  
	 for ascii_char in range(32, 123):  
			char = ascii_char >> index % 8 ^ ascii_char  
			if char == target_char:  
				print(f'{chr(ascii_char)}', end='', flush=True)  

	encoded = "\000dslp}oQ\000 dks$|M\000h +AYQg\000P*!M$gQ\000"  
	reversed_encoded = encoded[::-1]  
	for index, target_char in enumerate(reversed_encoded):  
		get_possible_chars(index, target_char)
	```
* The script produced the following string: ```?ay I *P?EASE* h?ve the ?assword?```, which we could easily complete to "May I \*PLEASE\* have the password?". And indeed, Boris reacted to our message with the third and last flag:
</br>![Alt_Text](images/Pasted%20image%2020211204170007.png)

---
## Conclusion
* This CTF included frida hooking, password recon and cracking and encryption reverse engineering challenges.
* The creator of the CTF ranked the difficulty level of the challenges from easy to hard, but in my humble opinion, most of the challenges should be ranked easy, and only the third one ("Login") might be ranked as medium.
* I approached this CTF as a part of a training session to an interview. As a vetern CTf player, I encountered challenge types I recognized from Windows and Linux CTFs, but also had the opportunity to experiment with things unique to android, such as frida hooking, app structure and more.
* All in all an excellent entry level CTF for Android, with a good veraity of challenges and an added value in adding unique knowledge for Android.
