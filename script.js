Java.perform(function () {

  try{
    // Use the IncomingTextMessage class
    var incomingTextMessageClass = Java.use('org.thoughtcrime.securesms.sms.IncomingTextMessage');
    // Hook the original implementation of the getMessageBody() method
    incomingTextMessageClass.getMessageBody.implementation = function() {
      var messageBody = this.getMessageBody();
      var receivedTime = this.getReceivedTimestampMillis();
      var senderIdWithText = this.getSender().toString()
      // Filtering the 'RecipientId::' out and taking only the ID
      var senderId = senderIdWithText.substring(senderIdWithText.length - 1);
      console.log('Intercepted incoming message at ' + receivedTime +  ' : ' + messageBody + ' (from sender ID ' + senderId + ')');
      // Insert message into SQLite database
      sendMessage(receivedTime, messageBody, senderId);
      // Return the original message body
      return messageBody;
    };

    // A function to insert the intercepted message into an SQLite database
    function sendMessage(receivedTime, messageBody, senderId) {
      var message = {
      receivedTime: receivedTime,
      messageBody: messageBody,
      senderId: senderId
      };
      send(message);
    }

  } catch (e) {
    // Handle errors that occurred while executing the script
    if (e.message && e.message.includes('java.lang.ClassNotFoundException')) {
      console.error('Error: Could not find class', e);
    } else {
      console.error('Unexpected error in script:', e);
    }
  }


});
