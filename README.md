# Hook Signal using Frida

This project provides a script to intercept incoming messages in the Signal Android app using Frida. The script is written in Python and JavaScript and uses SQLite to store the intercepted messages.

## How it works
The script uses Frida to hook the `org.thoughtcrime.securesms.sms.IncomingTextMessage` Java class in the Signal app. Whenever a new text message is received, the `getMessageBody()` method of the `IncomingTextMessage` class is intercepted by the script, and the intercepted message, its received timestamp in milliseconds and a sender ID number are sent to the Python script. The Python script then stores the intercepted message info in a local SQLite database.

## Prerequisites
* An Android device
* Python 3.x installed
* The frida Python package installed
* The frida-server running on the Android device
* The Signal app installed on the Android device

## Usage
1. Connect your Android device to your machine and make sure you have enabled debugging on it.
   For example, as I did:
   ```bash
   $ adb devices
   List of devices attached
   127.0.0.1:5555	device
   ```
2. Start the frida-server on your Android device. For example, as I did:
    ```bash
    $ adb -s 127.0.0.1:5555 shell
    vbox86p:/ # cd /data/local/tmp
    vbox86p:/data/local/tmp # ./frida-server-16.0.11-android-x86_64
    ```
3. From another terminal window, navigate to this project directory on your machine and run:
    ```bash
   $ python3 hook.py
   ```
   
4. You can now send messages to the Android device Signal user, and see output. For example: 
   ```bash
   $ python3 hook.py
   Press Enter to exit...
   Intercepted incoming message at 1679835421436 : Dean (from sender ID 4)
   Intercepted incoming message at 1679835423294 : Simple (from sender ID 5)
   Intercepted incoming message at 1679835426354 : Example (from sender ID 5)
   ```
5. When you sent enough messages, press Enter. Then from the same terminal, you can query the database and see the stored data as follows:

   ```bash
   $ sqlite3 signal_new_incoming_messages.db
   SQLite version 3.32.3 2020-06-18 14:16:19
   Enter ".help" for usage hints.
   sqlite> select * from messages;
   1679835421436|Dean|4
   1679835423294|Simple|5
   1679835426354|Example|5
   ```
   
