package org.fd.montoyatutorial;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.*;

public class CustomHttpRequestResponseEditor implements HttpRequestEditorProvider, HttpResponseEditorProvider {

    MontoyaApi api;

    public CustomHttpRequestResponseEditor(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext) {
        return new CustomHttpRequestEditorTab(api, creationContext);
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext creationContext) {
        return new CustomHttpResponseEditorTab(api, creationContext);
    }
}
