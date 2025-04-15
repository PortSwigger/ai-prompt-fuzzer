import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ai.chat.Message;
import burp.api.montoya.ai.chat.Prompt;
import burp.api.montoya.ai.chat.PromptException;
import burp.api.montoya.ai.chat.PromptResponse;

import java.util.Random;

public class aIEnabled implements aiInterface {
    MontoyaApi api = AI_Prompt_Fuzzer.getApi();

    @Override
    public boolean isEnabled() {
        return api.ai().isEnabled();
    }

    @Override
    public Prompt prompt() {
        return api.ai().prompt();
    }

    public String getSingle_AI_Response(String systemPrompt, String userPrompt, boolean fakeResponse) {
        if (!api.ai().isEnabled()) {
            api.logging().logToOutput("[i]: AI is not enabled, please review AI settings and credits.");
            return "";
        }
        // Reduce the Temperature (default is 0.5)
        //PromptOptions options = PromptOptions.promptOptions()
        //        .withTemperature(0.3);

        // Define the AI's role with a system message

        Message systemMessage = Message.systemMessage(systemPrompt);

        // Provide a user query with a user message
        Message userMessage = Message.userMessage(userPrompt);

        // check if fakeResponse is true respond with random fake response to avoid using credits while testing
        if (fakeResponse) {
            String[] values = {"Positive", "Negative", "AI error/invalid response"};
            Random r = new Random();
            String result = values[r.nextInt(values.length)];
            api.logging().logToOutput("[i]: Fake AI Response: " + result);
            return result;
        }

        // Send the prompt and get the response
        try {
            PromptResponse response = api.ai().prompt().execute(systemMessage, userMessage);
            // Retrieve the AI's response content
            return response.content();
        } catch (PromptException e) {
            api.logging().logToOutput("An error occurred while communicating with the AI: " + e.getMessage());
            return "";
        }
    }
}

