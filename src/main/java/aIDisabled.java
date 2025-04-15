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

    @Override
    public String getSingle_AI_Response(String systemPrompt, String userPrompt, boolean fakeResponse) {
        return "";
    }
}

