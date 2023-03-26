import frida
import sqlite3


# Callback function on_message that will be called whenever the injected script running inside the Signal app sends
# a message
def message_handler():
    def on_message(message, data):
        if message['type'] == 'error':
            print('Error message:', message['description'])
            print('Stack trace:', message['stack'])
        if message['type'] == 'send':
            timestamp = message['payload']['receivedTime']
            message_text = message['payload']['messageBody']
            sender_id = message['payload']['senderId']
            with sqlite3.connect('signal_new_incoming_messages.db') as db_conn:
                db = db_conn.cursor()
                db.execute('INSERT INTO messages (timestamp, message, senderId) VALUES (?, ?, ?)', (timestamp, message_text, sender_id))
                db_conn.commit()

    return on_message


def main():
    # Establish connection to db
    db_conn = sqlite3.connect('signal_new_incoming_messages.db')
    with db_conn:
        db = db_conn.cursor()
        db.execute('CREATE TABLE IF NOT EXISTS messages (timestamp INTEGER, message TEXT, senderId TEXT)')

    # Attaching the Signal process and load script.js into it
    process = frida.get_usb_device().attach('Signal')
    with open('script.js', 'r') as f:
        script = process.create_script(f.read())

    # Set the .py message_handler() to be invoked whenever
    # a message is being sent by script.js
    on_message = message_handler()
    script.on('message', on_message)
    script.load()

    # Wait for user to exit
    input('Press Enter to exit...\n')


if __name__ == '__main__':
    main()
