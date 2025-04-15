import burp.api.montoya.ai.chat.Prompt;

public interface aiInterface {
    boolean isEnabled();
    Prompt prompt();
    String getSingle_AI_Response(String systemPrompt, String userPrompt, boolean fakeResponse);
}
