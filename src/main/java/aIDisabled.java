import burp.api.montoya.ai.chat.Message;
import burp.api.montoya.ai.chat.Prompt;

public class aIDisabled implements aiInterface {

    @Override
    public boolean isEnabled() {
        return false;
    }

    @Override
    public Prompt prompt() {
        return null;
    }

    public String getSingle_AI_Response(String systemPrompt, String userPrompt, boolean fakeResponse) {
        return "";
    }

    // Adds a new user query and sends the updated context
    public String addUserQueryToConversation(String systemPrompt, String userPrompt) {
        return "";
    }
}

