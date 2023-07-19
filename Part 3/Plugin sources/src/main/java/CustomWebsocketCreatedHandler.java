import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.websocket.WebSocket;
import burp.api.montoya.websocket.WebSocketCreated;
import burp.api.montoya.websocket.WebSocketCreatedHandler;

public class CustomWebsocketCreatedHandler implements WebSocketCreatedHandler {

    MontoyaApi api;
    Logging logging;

    public CustomWebsocketCreatedHandler(MontoyaApi api) {
        // Save a reference to the MontoyaApi object
        this.api = api;
        // api.logging() returns an object that we can use to print messages to stdout and stderr
        this.logging = api.logging();
    }

    @Override
    public void handleWebSocketCreated(WebSocketCreated webSocketCreated) {
        // Get a reference to the created WebSocket
        WebSocket websocket = webSocketCreated.webSocket();
        // Register a listener to handle bidiretional messages of the WebSocket
        websocket.registerMessageHandler(new CustomWebsocketHandler(api));
    }

}
