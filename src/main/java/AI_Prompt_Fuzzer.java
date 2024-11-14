import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.HttpService;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.SwingWorker;
import java.awt.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URI;
import java.awt.event.*;

// Imports for parsing XML files
import javax.swing.table.TableRowSorter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.w3c.dom.Element;
import java.io.File;

// Imports for URL Encoding
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class AI_Prompt_Fuzzer implements BurpExtension {

    private MontoyaApi api;
    private List<String> payloads = new ArrayList<>();
    private String placeholder = "[PLACEHOLDER]";
    private static JTextArea requestArea;
    private static HttpService currentHttpService;
    private static HttpRequest currentRequest;
    private static final int THREAD_POOL_SIZE = 10; // Number of threads in the pool
    // Components for the splitpane
    private JTable logTable;
    private DefaultTableModel logTableModel;
    private JTextArea requestResponseViewer;
    // Payload list
    private NodeList payloadList;
    // Instance variables for UI components
    private JProgressBar progressBar; // Add a progress bar reference
    private JPanel buttonPanel; // Declare buttonPanel
    // SendPayloads button to be accessed by other methods
    JButton sendRequestsButton = new JButton("Send Payloads");
    // URL encoding option
    private JCheckBox urlEncodePayloads = new JCheckBox("URLEncode payloads");
    // escape (") and (\) option
    JCheckBox escapeSpecialChars = new JCheckBox("Escape (\") and (\\) in payloads");

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("AI Prompt Fuzzer");
        api.userInterface().registerContextMenuItemsProvider(new MyContextMenuItemsProvider(api));
        SwingUtilities.invokeLater(this::createUI);
        api.logging().logToOutput("[i]: Loaded Successfully");
    }

    private void createUI() {
        JPanel mainPanel = new JPanel(new BorderLayout());

        // Request text area setup with title
        requestArea = new JTextArea(10, 50);
        JScrollPane requestScrollPane = new JScrollPane(requestArea);
        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(BorderFactory.createTitledBorder("Request to be sent (remember to add a PlaceHolder)"));
        requestPanel.add(requestScrollPane, BorderLayout.CENTER);
        mainPanel.add(requestPanel, BorderLayout.WEST);

        // Log Table setup with title
        logTableModel = new DefaultTableModel(new Object[]{"Time", "Method", "URL", "Status",
                "Length", "Request", "Response", "Potential Break"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false; // Make the table cells non-editable
            }
        };
        logTable = new JTable(logTableModel);
        logTable.removeColumn(logTable.getColumn("Request")); // Hide "Request" column
        logTable.removeColumn(logTable.getColumn("Response")); // Hide "Response" column

        // Add sorting
        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(logTableModel);
        logTable.setRowSorter(sorter);

        JScrollPane logScrollPane = new JScrollPane(logTable);
        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(BorderFactory.createTitledBorder("Requests and Responses Log"));
        logPanel.add(logScrollPane, BorderLayout.CENTER);

        // Request/Response Viewer with title
        requestResponseViewer = new JTextArea(10, 50);
        requestResponseViewer.setEditable(false);
        JScrollPane viewerScrollPane = new JScrollPane(requestResponseViewer);
        JPanel viewerPanel = new JPanel(new BorderLayout());
        viewerPanel.setBorder(BorderFactory.createTitledBorder("Request and Response Viewer"));
        viewerPanel.add(viewerScrollPane, BorderLayout.CENTER);

        // Create a JSplitPane for log table and request/response viewer
        JSplitPane verticalSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, logPanel, viewerPanel);

        // Create a JSplitPane to allow resizing between requestArea (WEST) and log/viewer (CENTER)
        JSplitPane horizontalSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestPanel, verticalSplitPane);

        // Set the divider location based on the Burp Suite window's current width and Height
        mainPanel.addHierarchyListener(e -> {
            if ((e.getChangeFlags() & HierarchyEvent.SHOWING_CHANGED) != 0 && mainPanel.isShowing()) {
                int burpWindowWidth = mainPanel.getWidth();
                horizontalSplitPane.setDividerLocation(burpWindowWidth * 40 / 100);
                int burpWindowHeight = mainPanel.getHeight();
                verticalSplitPane.setDividerLocation(burpWindowHeight * 40 / 100);
            }
        });

        mainPanel.add(horizontalSplitPane, BorderLayout.CENTER);

        // Create button panel for Load, Send, Clear, and Insert Placeholder buttons
        buttonPanel = new JPanel();
        buttonPanel.setLayout(new FlowLayout(FlowLayout.LEFT));

        JButton loadPayloadButton = new JButton("Load Payloads");
        loadPayloadButton.addActionListener(e -> loadPayloads());
        buttonPanel.add(loadPayloadButton);

        // Adds sendRequests button as disabled
        sendRequestsButton.addActionListener(e -> sendRequests());
        buttonPanel.add(sendRequestsButton);

        JButton clearLogButton = new JButton("Clear Log");
        clearLogButton.addActionListener(e -> clearLog());
        buttonPanel.add(clearLogButton);

        JButton insertPlaceholderButton = new JButton("Insert Placeholder");
        insertPlaceholderButton.addActionListener(e -> insertPlaceholder());
        buttonPanel.add(insertPlaceholderButton);

        // Add the "About" button to the button panel
        JButton aboutButton = new JButton("About");
        aboutButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showAboutDialog();
            }
        });
        buttonPanel.add(aboutButton);

        // JPanel for the payload settings
        JPanel payloadSettings = new JPanel();
        payloadSettings.setLayout(new FlowLayout(FlowLayout.LEFT));

        // Add payload options
        payloadSettings.add(urlEncodePayloads);
        escapeSpecialChars.setSelected(true);
        payloadSettings.add(escapeSpecialChars);

        // Footer label panel
        JPanel footerPanel = new JPanel(new BorderLayout());
        JLabel footerLabel = new JLabel("Developed by Idris", JLabel.LEFT);
        footerPanel.add(footerLabel, BorderLayout.EAST); // Align the label to the right

        // South panel combining button panel and footer label
        JPanel southPanel = new JPanel(new BorderLayout());
        southPanel.add(buttonPanel, BorderLayout.WEST);
        southPanel.add(footerPanel, BorderLayout.EAST);
        southPanel.add(payloadSettings,BorderLayout.SOUTH);

        mainPanel.add(southPanel, BorderLayout.SOUTH); // Add southPanel to the main panel

        // Add right-click menu to the request/response viewer and log table
        addRightClickMenus();

        api.userInterface().registerSuiteTab("AI Prompt Fuzzer", mainPanel);

        logTable.getSelectionModel().addListSelectionListener(e -> updateRequestResponseViewer());

        // Add a mouse listener to the table header to detect right-clicks and reset sorting
        logTable.getTableHeader().addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                // Check if the right button was clicked
                if (SwingUtilities.isRightMouseButton(e)) {
                    // Clear the sort keys to reset sorting to the original order
                    sorter.setSortKeys(null);
                }
            }
        });
    }

    // Method to create right-click menus for requestArea and requestResponseViewer
    private void addRightClickMenus() {
        // Popup menu for requestArea with Send to Repeater, Send to Intruder, Copy, Cut, and Paste
        JPopupMenu requestAreaPopupMenu = new JPopupMenu();

        // Copy option
        JMenuItem copyItemRequestArea = new JMenuItem("Copy");
        copyItemRequestArea.addActionListener(e -> requestArea.copy());
        requestAreaPopupMenu.add(copyItemRequestArea);

        // Cut option
        JMenuItem cutItemRequestArea = new JMenuItem("Cut");
        cutItemRequestArea.addActionListener(e -> requestArea.cut());
        requestAreaPopupMenu.add(cutItemRequestArea);

        // Paste option
        JMenuItem pasteItemRequestArea = new JMenuItem("Paste");
        pasteItemRequestArea.addActionListener(e -> requestArea.paste());
        requestAreaPopupMenu.add(pasteItemRequestArea);

        // Attach requestAreaPopupMenu to requestArea only
        requestArea.setComponentPopupMenu(requestAreaPopupMenu);

        // Popup menu for requestResponseViewer with Copy, Send to Repeater, and Send to Intruder only
        JPopupMenu viewerPopupMenu = new JPopupMenu();

        // Copy option
        JMenuItem copyItemViewer = new JMenuItem("Copy");
        copyItemViewer.addActionListener(e -> requestResponseViewer.copy());
        viewerPopupMenu.add(copyItemViewer);

        // Separator
        viewerPopupMenu.addSeparator();

        // Send to Repeater and Send to Intruder for requestResponseViewer
        JMenuItem sendToRepeaterItemViewer = new JMenuItem("Send to Repeater");
        sendToRepeaterItemViewer.addActionListener(e -> sendToRepeater());
        viewerPopupMenu.add(sendToRepeaterItemViewer);

        JMenuItem sendToIntruderItemViewer = new JMenuItem("Send to Intruder");
        sendToIntruderItemViewer.addActionListener(e -> sendToIntruder());
        viewerPopupMenu.add(sendToIntruderItemViewer);

        // Attach viewerPopupMenu to requestResponseViewer only
        requestResponseViewer.setComponentPopupMenu(viewerPopupMenu);

        // Popup menu for logTable with only Send to Repeater and Send to Intruder
        JPopupMenu logTablePopupMenu = new JPopupMenu();

        JMenuItem sendToRepeaterItemTable = new JMenuItem("Send to Repeater");
        sendToRepeaterItemTable.addActionListener(e -> sendToRepeater());
        logTablePopupMenu.add(sendToRepeaterItemTable);

        JMenuItem sendToIntruderItemTable = new JMenuItem("Send to Intruder");
        sendToIntruderItemTable.addActionListener(e -> sendToIntruder());
        logTablePopupMenu.add(sendToIntruderItemTable);

        // Attach logTablePopupMenu to logTable only
        logTable.setComponentPopupMenu(logTablePopupMenu);

        // Ensure the logTable selects the right-clicked row
        logTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                int row = logTable.rowAtPoint(e.getPoint());
                if (row >= 0 && e.getButton() == java.awt.event.MouseEvent.BUTTON3) {  // Right-click detected
                    logTable.setRowSelectionInterval(row, row); // Select the row at the clicked point
                }
            }
        });
    }

    // Method to send the current request to the Repeater
    private void sendToRepeater() {
        int selectedRow = logTable.getSelectedRow();
        if (selectedRow >= 0) {
            int modelRow = logTable.convertRowIndexToModel(selectedRow);
            HttpRequest request = (HttpRequest) logTableModel.getValueAt(modelRow, 5);
            if (request != null) {
                // Sending the selected request to Repeater
                api.repeater().sendToRepeater(request);
                JOptionPane.showMessageDialog(null, "Request sent to Repeater.");
            } else {
                JOptionPane.showMessageDialog(null, "No request selected to send to Repeater.");
            }
        }
    }

    // Method to send the current request to the Intruder
    private void sendToIntruder() {
        int selectedRow = logTable.getSelectedRow();
        if (selectedRow >= 0) {
            int modelRow = logTable.convertRowIndexToModel(selectedRow);
            HttpRequest request = (HttpRequest) logTableModel.getValueAt(modelRow, 5);
            if (request != null) {
                // Sending the selected request to Intruder
                api.intruder().sendToIntruder(request);
                JOptionPane.showMessageDialog(null, "Request sent to Intruder.");
            } else {
                JOptionPane.showMessageDialog(null, "No request selected to send to Intruder.");
            }
        }
    }

    // Method to clear the log table and request/response viewer
    private void clearLog() {
        // Clear all rows in the log table
        logTableModel.setRowCount(0);

        // Clear the request/response viewer
        requestResponseViewer.setText("");
    }

    // Method to insert or replace with [PLACEHOLDER] in requestArea
    private void insertPlaceholder() {
        String placeholder = "[PLACEHOLDER]";
        int start = requestArea.getSelectionStart();
        int end = requestArea.getSelectionEnd();

        if (start != end) {
            // If there is highlighted text, replace it with [PLACEHOLDER]
            requestArea.replaceRange(placeholder, start, end);
        } else {
            // Otherwise, insert [PLACEHOLDER] at the cursor position
            requestArea.insert(placeholder, start);
        }

        // Move the cursor to the end of the inserted placeholder
        requestArea.setCaretPosition(start + placeholder.length());
    }

    // Method to show the "About" dialog
    private void showAboutDialog() {
        // Create a modal dialog
        JDialog aboutDialog = new JDialog((Frame) null, "About AI Prompt Fuzzer", true);
        aboutDialog.setSize(400, 200);
        aboutDialog.setLayout(new BorderLayout(10, 10));

        // Create a panel with padding for a boxed look, without a title
        JPanel messagePanel = new JPanel();
        messagePanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10)); // Padding only

        // Setting up GridBagLayout for vertical alignment and centered positioning
        messagePanel.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.insets = new Insets(5, 0, 5, 0); // Add some padding between labels
        gbc.anchor = GridBagConstraints.CENTER;

        // Label for version and developer information
        JLabel toolNameLabel = new JLabel("AI Prompt Fuzzer v1.0", JLabel.CENTER);
        toolNameLabel.setFont(new Font("SansSerif", Font.BOLD, 14));

        JLabel devNameLabel = new JLabel("Developed by Mohamed Idris", JLabel.CENTER);
        devNameLabel.setFont(new Font("SansSerif", Font.BOLD, 14));

        // Add labels to messagePanel with vertical alignment
        messagePanel.add(toolNameLabel, gbc);
        gbc.gridy++; // Move to the next row for the second label
        messagePanel.add(devNameLabel, gbc);

        // Hyperlink-style label for help and additional information
        JLabel linkLabel = new JLabel("Help and Additional Information", JLabel.CENTER);
        linkLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
        linkLabel.setForeground(Color.BLUE.darker());
        linkLabel.setCursor(new Cursor(Cursor.HAND_CURSOR));
        linkLabel.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                try {
                    Desktop.getDesktop().browse(new URI("https://github.com/moha99sa/AI_Prompt_Fuzzer"));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        });

        // Add the link label to the bottom of the messagePanel
        gbc.gridy++; // Move to the next row for the second label
        messagePanel.add(linkLabel, gbc);

        // Add messagePanel to the Dialog
        aboutDialog.add(messagePanel, BorderLayout.CENTER);

        // Center the dialog on the screen
        aboutDialog.setLocationRelativeTo(null);
        aboutDialog.setVisible(true);
    }

    // Load payloads from the XML file
    private void loadPayloads() {
        try {
            // Create a file chooser
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Select an XML file");

            // Show the open dialog and check if a file was selected
            int userSelection = fileChooser.showOpenDialog(null);

            if (userSelection == JFileChooser.APPROVE_OPTION) {
                // Get the selected file
                File xmlFile = fileChooser.getSelectedFile();
                //System.out.println("Selected file: " + xmlFile.getAbsolutePath());

                // Initialize the DocumentBuilderFactory
                DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
                DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
                Document doc = dBuilder.parse(xmlFile);

                // Normalize XML structure
                doc.getDocumentElement().normalize();

                // Get all <payload> elements
                payloadList = doc.getElementsByTagName("payload");
                JOptionPane.showMessageDialog(null, "Payloads loaded: " + payloadList.getLength());
                // Enable Send Requests button
                sendRequestsButton.setEnabled(true);
            } else {
                JOptionPane.showMessageDialog(null, "No file selected.");
            }
        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(null, "Error loading payloads. Please use valid XML payloads file");
        }
    }

    private void sendRequests() {
        if (!requestArea.getText().isEmpty() && payloadList != null && payloadList.getLength() > 0) {
            // Check if the current request is valid
            if (currentHttpService == null || currentHttpService.toString().isEmpty()){
                JOptionPane.showMessageDialog(null, "Invalid request, please send a valid request from any other Burp tool.");
                return;
            }

            // Disable Send Requests button
            sendRequestsButton.setEnabled(false);

            int totalPayloads = payloadList.getLength();
            String originalRequestStr = requestArea.getText();

            // Check if user forgets to add a Placeholder
            if (!originalRequestStr.contains(placeholder)){
                int userResponse = JOptionPane.showConfirmDialog(
                        null,
                        "Placeholder string not found in the request!\nDo you still want to continue?",
                        "No Placeholder found",
                        JOptionPane.YES_NO_OPTION,
                        JOptionPane.QUESTION_MESSAGE
                );
                if (userResponse != JOptionPane.YES_OPTION) {
                    // Enable Send Requests button
                    sendRequestsButton.setEnabled(true);
                    return;
                }
            }

            // Check if user forgets to use URL encoding for a GET request
            HttpRequest thisRequest = HttpRequest.httpRequest(currentHttpService, originalRequestStr);
            if (Objects.equals(thisRequest.method(), "GET") && !urlEncodePayloads.isSelected()){
                int userResponse = JOptionPane.showConfirmDialog(
                        null,
                        "Seems like you are trying to send a GET request while URLEncode payload option is not selected." +
                                " Sending clear-text payloads over URL may result on errors.\nDo you still want to continue?",
                        "GET request without URL encoding",
                        JOptionPane.YES_NO_OPTION,
                        JOptionPane.QUESTION_MESSAGE
                );
                if (userResponse != JOptionPane.YES_OPTION) {
                    // Enable Send Requests button
                    sendRequestsButton.setEnabled(true);
                    return;
                }
            }

            // Create a progress bar and add it above the "Send Payloads" button
            JProgressBar progressBar = new JProgressBar(0, 100);
            progressBar.setStringPainted(true);
            buttonPanel.add(progressBar); // Add progress bar at the top of the button panel
            buttonPanel.revalidate();
            buttonPanel.repaint();

            // Create a SwingWorker for background processing
            SwingWorker<Void, Integer> worker = new SwingWorker<Void, Integer>() {
                private int completedRequests = 0; // Track the number of completed requests

                @Override
                protected Void doInBackground() throws Exception {
                    // Use thread pool to send requests asynchronously
                    ExecutorService executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);

                    for (int i = 0; i < totalPayloads; i++) {
                        final int currentIndex = i; // Create a final copy of i for use in the lambda

                        Element payloadElement = (Element) payloadList.item(i);

                        // Get <inject> and <validate> elements
                        String inject = payloadElement.getElementsByTagName("inject").item(0).getTextContent();
                        String validate = payloadElement.getElementsByTagName("validate").item(0).getTextContent();

                        // Apply payload options before sending
                        String configuredInject = inject;
                        // Escape special characters in the payload
                        if (escapeSpecialChars.isSelected()) {
                            // Escape only double quotes and backslashes in the inject string
                            configuredInject = inject.replaceAll("([\"\\\\])", "\\\\$1");
                        };
                        // URL encode the payload
                        if (urlEncodePayloads.isSelected()) {
                            configuredInject = URLEncoder.encode(configuredInject, StandardCharsets.UTF_8);
                        };

                        // Replace Placeholder with the current payload
                        String modifiedRequestStr = originalRequestStr.replace(placeholder, configuredInject);

                        try {
                            // Remove HTTP headers that cause issues with the replay request
                            HttpRequest modifiedRequest = HttpRequest.httpRequest(currentHttpService, modifiedRequestStr)
                                    .withRemovedHeader("Content-Length")
                                    .withRemovedHeader("If-Modified-Since")
                                    .withRemovedHeader("If-None-Match");

                            if (modifiedRequest.hasHeader("Host") && !modifiedRequest.method().isEmpty()) {
                                Runnable requestTask = () -> {
                                    try {
                                        HttpResponse response = api.http().sendRequest(modifiedRequest).response();

                                        // Logic for identifying if the request is valid potential
                                        // Normalize strings by removing special characters
                                        String normalizedInject = normalizeString(inject);
                                        String normalizedValidate = normalizeString(validate);
                                        String normalizedResponseBody = normalizeString(response.body().toString());
                                        // Remove the entire inject string from the response before checking
                                        String cleanedResponseBody = normalizedResponseBody.replaceAll(normalizedInject, "");

                                        // Check if the cleaned response body contains the normalized validate string to be a potential break
                                        boolean isValid = cleanedResponseBody.contains(normalizedValidate);

                                        logRequestResponse(modifiedRequest, response, isValid);

                                        // Update completed requests and publish overall progress
                                        synchronized (this) {
                                            completedRequests++;
                                            int progress = (completedRequests * 100) / totalPayloads;
                                            publish(progress); // Update progress
                                        }

                                        // Small delay between requests to avoid overwhelming the system
                                        TimeUnit.MILLISECONDS.sleep(100);
                                    } catch (Exception e) {
                                        JOptionPane.showMessageDialog(null, "Error processing request: " + e.getMessage());
                                        // Enable Send Requests button
                                        sendRequestsButton.setEnabled(true);
                                    }
                                };
                                executor.submit(requestTask);
                            } else {
                                JOptionPane.showMessageDialog(null, "Selected Request is invalid.");
                                // Enable Send Requests button
                                sendRequestsButton.setEnabled(true);
                                return null;
                            }
                        } catch (Exception e) {
                            JOptionPane.showMessageDialog(null, "Error while building the request: " + e.getMessage());
                            // Enable Send Requests button
                            sendRequestsButton.setEnabled(true);
                            return null;
                        }
                    }

                    // Shutdown the executor gracefully
                    executor.shutdown();
                    executor.awaitTermination(1, TimeUnit.MINUTES);
                    // Enable Send Requests button
                    sendRequestsButton.setEnabled(true);
                    return null;
                }

                @Override
                protected void process(List<Integer> chunks) {
                    int latestProgress = chunks.get(chunks.size() - 1);
                    progressBar.setValue(latestProgress); // Set progress bar to latest value
                }

                @Override
                protected void done() {
                    buttonPanel.remove(progressBar); // Remove progress bar after completion
                    buttonPanel.revalidate();
                    buttonPanel.repaint();
                }
            };

            worker.execute(); // Start the SwingWorker task
        }
        else {
            JOptionPane.showMessageDialog(null, "No payloads loaded or request selected.");
            // Enable Send Requests button
            sendRequestsButton.setEnabled(true);
        }
    }

    // Log request-response pair in the table with columns: Time, Method, URL, Status, and Length
    private void logRequestResponse(HttpRequest request, HttpResponse response, boolean isValid) {
        SwingUtilities.invokeLater(() -> {
            String method = request.method().toString();
            String url = request.url().toString();
            String status = String.valueOf(response.statusCode());
            int length = response.body().length(); // Calculate the response length
            // Convert the isValid boolean to uppercase string
            String isValidStr = isValid ? "TRUE" : "FALSE"; // Convert to uppercase strings
            String recordTime = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss.SSS"));

            // Add the request, response, and additional details to the table model
            logTableModel.addRow(new Object[]{recordTime, method, url, status, Integer.toString(length), request, response, isValidStr});
            // Apply the custom renderer to the table
            for (int i = 0; i < logTable.getColumnCount(); i++) {
                logTable.getColumnModel().getColumn(i).setCellRenderer(new CustomRenderer());
            }
        });
    }

    // Normalize strings by removing special characters and Unicode representations
    private static String normalizeString(String input) {
        // Remove unicode characters represented as "\\uXXXX"

        // Remove special characters
        String withoutSpecialChars = input.replaceAll("[\\\\'\"@%\\[\\]{}?!/<>^&$()|~#]", "");

        return withoutSpecialChars;
    }

    // Update request-response viewer when a row in the table is selected
    private void updateRequestResponseViewer() {
        int selectedRow = logTable.getSelectedRow();
        if (selectedRow >= 0) {
            // Convert the view row index to the model row index
            int modelRow = logTable.convertRowIndexToModel(selectedRow);
            HttpRequest request = (HttpRequest) logTableModel.getValueAt(modelRow, 5);
            HttpResponse response = (HttpResponse) logTableModel.getValueAt(modelRow, 6);
            requestResponseViewer.setText("Request:\n" + request.toString() + "\n\nResponse:\n" + response.toString());
            // Scroll to the top of the requestResponseViewer
            requestResponseViewer.setCaretPosition(0);
        }
    }

    public static void setCurrentRequestResponse(HttpRequestResponse parRequestResponse) {
        if (parRequestResponse != null) {
            currentHttpService = parRequestResponse.httpService();
            requestArea.setText(parRequestResponse.request().toString());
        }
    }
}

class CustomRenderer extends DefaultTableCellRenderer {
    private static final Color HIGHLIGHT_COLOR = Color.YELLOW;
    private static final Color EVEN_ROW_COLOR = new Color(240, 240, 240); // Light gray for even rows
    private static final Color ODD_ROW_COLOR = Color.WHITE;               // White for odd rows

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        // Call parent to get default rendering
        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        // Use view row index for consistent coloring after sorting
        int viewRow = table.convertRowIndexToModel(row);

        // Get the isValid flag from the model, at the view's row index
        String isValid = (String) table.getModel().getValueAt(viewRow, 7); // Column index 7 for "Potential Break" status

        if (isSelected) {
            // Use selection colors if the cell is selected
            c.setBackground(table.getSelectionBackground());
            c.setForeground(table.getSelectionForeground());
        } else if ("TRUE".equals(isValid)) {
            // Highlight row if "Potential Break" is marked TRUE
            c.setBackground(HIGHLIGHT_COLOR);
            c.setForeground(Color.BLACK);
        } else {
            // Apply banding for non-highlighted rows
            if (row % 2 == 0) {
                c.setBackground(EVEN_ROW_COLOR);  // Light gray for even rows
            } else {
                c.setBackground(ODD_ROW_COLOR);   // White for odd rows
            }
            c.setForeground(Color.BLACK);  // Default text color for unselected cells
        }

        // Ensure the renderer is opaque to show background color
        ((JComponent) c).setOpaque(true);

        return c;
    }
}