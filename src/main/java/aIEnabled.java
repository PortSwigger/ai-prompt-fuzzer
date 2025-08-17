import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ai.chat.Message;
import burp.api.montoya.ai.chat.Prompt;
import burp.api.montoya.ai.chat.PromptException;
import burp.api.montoya.ai.chat.PromptResponse;
import java.util.ArrayList;
import java.util.List;

import java.util.Random;

public class aIEnabled implements aiInterface {
    MontoyaApi api = AI_Prompt_Fuzzer.getApi();
    private List<Message> context = new ArrayList<>();

    @Override
    public boolean isEnabled() {
        return api.ai().isEnabled();
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

    // Initializes the conversation with a system message
    private void initializeConversationContext(String systemPrompt) {
        if (context.isEmpty()) {
            context.add(Message.systemMessage(systemPrompt));
        }
    }

    // Reset the conversation
    public void resetConversationContext(){
        context.clear();
    }

    // Adds a new user query and sends the updated context
    public String addUserQueryToConversation(String systemPrompt, String userPrompt) {
        initializeConversationContext(systemPrompt);  // Ensure system message exists
        context.add(Message.userMessage(userPrompt));

        //debug messages
        //api.logging().logToOutput("[i]: Sent Context:");
        //context.forEach(m -> api.logging().logToOutput(m.toString()));

        return sendConversationPrompt();
    }

    // Sends the prompt to the AI and updates the context
    private String sendConversationPrompt() {
        String result = "";
        try {
            // reducing context size to below 31 messages to reduce AI credits usage
            //trimContext();

            // Execute the prompt with the full context
            PromptResponse response = api.ai().prompt().execute(context.toArray(new Message[context.size()]));

            // Store AI response as an assistant message
            result = response.content();
            Message assistantMessage = Message.assistantMessage(response.content());
            context.add(assistantMessage);

        } catch (Exception e) {
            api.logging().logToOutput("[e]: Error processing AI response: " + e.getMessage());
        }
        return result;
    }

    private void trimContext(){
        int index = 1; // to avoid removing System message at index 0
        while (context.size() - 31 > 0) {
            api.logging().logToOutput("[i]: Context Size: " + context.size() + ", executing trimContext!");
            // removing the earliest user and assistant messages
            //api.logging().logToOutput("Removing: " + context.get(index));
            context.remove(index);
            //api.logging().logToOutput("Removing: " + context.get(index));
            context.remove(index);
            //api.logging().logToOutput("New item at index " + index + ": " + context.get(index));
        }
    }
}

