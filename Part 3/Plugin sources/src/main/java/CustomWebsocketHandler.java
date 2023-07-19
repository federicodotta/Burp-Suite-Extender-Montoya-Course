import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.utilities.Base64Utils;
import burp.api.montoya.utilities.CryptoUtils;
import burp.api.montoya.utilities.DigestAlgorithm;
import burp.api.montoya.websocket.*;

import java.math.BigInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CustomWebsocketHandler implements MessageHandler {

    MontoyaApi api;
    Logging logging;
    Base64Utils base64Utils;
    CryptoUtils cryptoUtils;

    public CustomWebsocketHandler(MontoyaApi api) {
        // Save a reference to the MontoyaApi object
        this.api = api;
        // Save a reference to the logging object, to print messages to stdoud and stderr
        this.logging = api.logging();
        // Save a reference to one utils for Base64 encoding and one for hashing operations
        this.base64Utils = api.utilities().base64Utils();
        this.cryptoUtils = api.utilities().cryptoUtils();
    }

    @Override
    public TextMessageAction handleTextMessage(TextMessage textMessage) {

        // Extract actual message and direction (client->server or server->client) from the TextMessage object
        String payload = textMessage.payload();
        Direction direction = textMessage.direction();

        // 1 - Take only messages containing my_event string sent from client to server
        if(payload.contains("my_event") && direction == Direction.CLIENT_TO_SERVER) {

            // 2 - Extract with a regex the actual message in the field "data" and the hash in the field "hash"
            Pattern p = Pattern.compile(".*\"data\"\\:\"([^\"]+)\".*\"hash\"\\:\"([^\"]+)\"");
            Matcher m = p.matcher(payload);

            // Check if the message has the expected structure, otherwise return original message
            if(m.find() && m.groupCount() == 2) {

                // 3 - Calculate SHA256 hash
                ByteArray sha256hash = cryptoUtils.generateDigest(ByteArray.byteArray(m.group(1)), DigestAlgorithm.SHA_256);

                // Convert SHA256 bytes to a HEX string, using a Java way
                String digest = String.format("%064x", new BigInteger(1, sha256hash.getBytes()));

                // 4 - Create a message with the hash updated
                String newMessage = payload.replaceAll(m.group(2), digest);

                // 5 - Print edited message
                logging.logToOutput("* Message with updated hash:");
                logging.logToOutput(newMessage);

                // 6 - Return the edited message
                return TextMessageAction.continueWith(newMessage);

            } else {

                logging.logToOutput("Data and hash not found. Returning original message.");
                return TextMessageAction.continueWith(textMessage);
            }

        }

        /*
        //DEBUG - Print text messages

        if (direction == Direction.CLIENT_TO_SERVER) {
            logging.logToOutput("T ==========>>");
        } else {
            logging.logToOutput("T <<==========");
        }

        logging.logToOutput(payload);
        logging.logToOutput("");
        */

        // Return orignal text message
        return TextMessageAction.continueWith(textMessage);

    }

    @Override
    public BinaryMessageAction handleBinaryMessage(BinaryMessage binaryMessage) {

        /*
        //DEBUG - Print binary messages

        // Extract actual message and direction form BinaryMessage object
        ByteArray payload = binaryMessage.payload();
        Direction direction = binaryMessage.direction();

        if(direction == Direction.CLIENT_TO_SERVER) {
            logging.logToOutput("B ==========>>");
        } else {
            logging.logToOutput("B <<==========");
        }

        logging.logToOutput(base64Utils.encodeToString(payload));
        logging.logToOutput("");
        */

        // Return original message
        return BinaryMessageAction.continueWith(binaryMessage);

    }
}
