import javax.swing.*;
import java.awt.*;
import java.util.Arrays;
import java.util.List;

public class RotatingHintBanner extends JPanel {

    private final List<String> messages = Arrays.asList(
            "Hint: to load default payloads, click on the View Payloads button or " +
                    "click the Load Payloads and then Cancel to use preloaded payloads.",
            "Clarification: when the response includes the payload sent, make sure to increase the value of " +
                    "the \"Minimum occurrences of the Keywords for potential break\" to 2 (number of occurrences + 1).",
            "Note: AI capabilities are supported only in specific Burp Suite Editions.",
            "Heads up: using AI to verify/review responses, consumes AI credits!",
            "Hint: to obtain better results from AI verification, use well written & structured prompts " +
                    "within your payloads.",
            "Tip: to temporarily edit a payload, click View Payloads, double click on the target payload to be edited, " +
                    "and click Ok after editing.",
            "Tip: use the Settings panel to customize your experience ;)",
            "Reminder: click on the About button for the help and documentation link"
    );

    private int messageIndex = 0;
    private final JLabel hintLabel;

    public RotatingHintBanner() {
        setLayout(new GridBagLayout()); // Center the label
        //setPreferredSize(new Dimension(600, 30));
        setOpaque(true);

        // Use the current Look and Feel colors (good for Burp Suite themes)
        Color background = UIManager.getColor("Panel.background");
        Color foreground = UIManager.getColor("Label.foreground");
        if (background != null) setBackground(background);
        if (foreground != null) setForeground(foreground);

        // Create label with initial hint
        hintLabel = new JLabel(messages.get(messageIndex));
        hintLabel.setFont(new Font("SansSerif", Font.PLAIN, 10));
        hintLabel.setForeground(foreground != null ? foreground : Color.BLACK);
        add(hintLabel);

        // Set up a timer to rotate messages every 10 seconds
        Timer timer = new Timer(10_000, e -> {
            messageIndex = (messageIndex + 1) % messages.size();
            hintLabel.setText(messages.get(messageIndex));
        });
        timer.start();

        // Add a border around the banner
        setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(UIManager.getColor("Separator.foreground"), 1),
                BorderFactory.createEmptyBorder(5, 10, 5, 10)
        ));
    }

    // Helper to plug into the banner panel
    public static void integrateWithUI(JPanel bannerPanel) {
        bannerPanel.setLayout(new BorderLayout());
        bannerPanel.add(new RotatingHintBanner(), BorderLayout.CENTER);
    }
}