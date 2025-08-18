import burp.api.montoya.ai.chat.Prompt;

public interface aiInterface {
    boolean isEnabled();
    String getSingle_AI_Response(String systemPrompt, String userPrompt, boolean fakeResponse);
    String addUserQueryToConversation(String systemPrompt, String newUserPrompt);
    void resetConversationContext();
}
