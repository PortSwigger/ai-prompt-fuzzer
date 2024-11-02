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
import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

// Imports for parsing XML files
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.w3c.dom.Element;
import java.io.File;
import java.util.regex.Pattern;

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
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, logPanel, viewerPanel);
        splitPane.setDividerLocation(250);
        mainPanel.add(splitPane, BorderLayout.CENTER);

        // Create button panel for Load, Send, Clear, and Insert Placeholder buttons
        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new FlowLayout(FlowLayout.LEFT));

        JButton loadPayloadButton = new JButton("Load Payloads");
        loadPayloadButton.addActionListener(e -> loadPayloads());
        buttonPanel.add(loadPayloadButton);

        JButton sendRequestsButton = new JButton("Send Payloads");
        sendRequestsButton.addActionListener(e -> sendRequests());
        buttonPanel.add(sendRequestsButton);

        JButton clearLogButton = new JButton("Clear Log");
        clearLogButton.addActionListener(e -> clearLog());
        buttonPanel.add(clearLogButton);

        JButton insertPlaceholderButton = new JButton("Insert Placeholder");
        insertPlaceholderButton.addActionListener(e -> insertPlaceholder());
        buttonPanel.add(insertPlaceholderButton);

        mainPanel.add(buttonPanel, BorderLayout.SOUTH);

        // Add right-click menu to the request/response viewer and log table
        addRightClickMenu();

        api.userInterface().registerSuiteTab("AI Prompt Fuzzer", mainPanel);

        logTable.getSelectionModel().addListSelectionListener(e -> updateRequestResponseViewer());
    }

    // Method to create a right-click menu for both requestResponseViewer and logTable
    private void addRightClickMenu() {
        // Create the popup menu
        JPopupMenu popupMenu = new JPopupMenu();

        // Add "Send to Repeater" menu item
        JMenuItem sendToRepeaterItem = new JMenuItem("Send to Repeater");
        sendToRepeaterItem.addActionListener(e -> sendToRepeater());
        popupMenu.add(sendToRepeaterItem);

        // Add "Send to Intruder" menu item
        JMenuItem sendToIntruderItem = new JMenuItem("Send to Intruder");
        sendToIntruderItem.addActionListener(e -> sendToIntruder());
        popupMenu.add(sendToIntruderItem);

        // Attach the popup menu to requestResponseViewer
        requestResponseViewer.setComponentPopupMenu(popupMenu);

        // Attach the popup menu to logTable with row selection handling
        logTable.setComponentPopupMenu(popupMenu);
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
            HttpRequest request = (HttpRequest) logTableModel.getValueAt(selectedRow, 5);
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
            HttpRequest request = (HttpRequest) logTableModel.getValueAt(selectedRow, 5);
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
            } else {
                JOptionPane.showMessageDialog(null, "No file selected.");
            }
        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(null, "Error loading payloads");
        }
    }

    private void sendRequests() {
        if (requestArea.getText() != null && payloadList.getLength() > 0) {
            String originalRequestStr = requestArea.getText();
            SwingWorker<Void, Object[]> worker = new SwingWorker<>() {
                @Override
                protected Void doInBackground() throws Exception {
                    ExecutorService executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);

                    for (int i = 0; i < payloadList.getLength(); i++) {
                        Element payloadElement = (Element) payloadList.item(i);

                        // Get <inject> and <validate> elements
                        String inject = payloadElement.getElementsByTagName("inject").item(0).getTextContent();
                        String validate = payloadElement.getElementsByTagName("validate").item(0).getTextContent();
                        String escapedInjectStr = inject.replaceAll("([\"\\\\])", "\\\\$1");
                        String modifiedRequestStr = originalRequestStr.replace(placeholder, escapedInjectStr);

                        try {
                            HttpRequest modifiedRequest = HttpRequest.httpRequest(currentHttpService, modifiedRequestStr)
                                    .withRemovedHeader("Content-Length")
                                    .withRemovedHeader("If-Modified-Since")
                                    .withRemovedHeader("If-None-Match");

                            if (modifiedRequest.hasHeader("Host") && !modifiedRequest.method().isEmpty()) {
                                Runnable requestTask = () -> {
                                    try {
                                        // Capture the time immediately before sending the request
                                        String sendTime = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
                                        HttpResponse response = api.http().sendRequest(modifiedRequest).response();

                                        // Escape and sanitize characters
                                        String escapedInject = inject.replaceAll("[\"'<>()]", "").replace("\\", "");
                                        String escapedValidate = validate.replaceAll("[\"'<>()]", "").replace("\\", "");
                                        String escapedResponseBody = response.body().toString().replaceAll("[\"'<>()]", "").replace("\\", "");
                                        escapedResponseBody = escapedResponseBody.replaceAll(escapedInject, ""); // Remove the inject string
                                        //api.logging().logToOutput("[Escaped Response: \n" + escapedResponseBody);

                                        // Check if the response body contains the validate string
                                        boolean isValid = escapedResponseBody.contains(escapedValidate);

                                        // Publish results for UI update
                                        publish(new Object[]{modifiedRequest, response, sendTime, isValid});

                                        // Small delay between requests to avoid overwhelming the system
                                        TimeUnit.MILLISECONDS.sleep(100);
                                    } catch (Exception e) {
                                        JOptionPane.showMessageDialog(null, "Error processing request: " + e.getMessage());
                                    }
                                };
                                executor.submit(requestTask);
                            } else {
                                JOptionPane.showMessageDialog(null, "Selected Request is invalid.");
                            }
                        } catch (Exception e) {
                            JOptionPane.showMessageDialog(null, "Error while building the request: " + e.getMessage());
                            return null;
                        }
                    }

                    // Shutdown the executor gracefully
                    executor.shutdown();
                    executor.awaitTermination(1, TimeUnit.MINUTES);
                    return null;
                }

                @Override
                protected void process(List<Object[]> chunks) {
                    // Update the log table with each chunk of results
                    for (Object[] chunk : chunks) {
                        HttpRequest request = (HttpRequest) chunk[0];
                        HttpResponse response = (HttpResponse) chunk[1];
                        String sendTime = (String) chunk[2];
                        boolean isValid = (boolean) chunk[3];
                        logRequestResponse(request, response, sendTime, isValid);
                    }
                }

                @Override
                protected void done() {
                    JOptionPane.showMessageDialog(null, "All requests have been sent.");
                }
            };

            worker.execute(); // Start the SwingWorker task
        } else {
            JOptionPane.showMessageDialog(null, "No payloads loaded or request selected.");
        }
    }

    // Log request-response pair in the table with columns: Time, Method, URL, Status, and Length
    private void logRequestResponse(HttpRequest request, HttpResponse response, String sendTime, boolean isValid) {
        SwingUtilities.invokeLater(() -> {
            String method = request.method().toString();
            String url = request.url().toString();
            String status = String.valueOf(response.statusCode());
            int length = response.body().length(); // Calculate the response length
            // Convert the isValid boolean to uppercase string
            String isValidStr = isValid ? "TRUE" : "FALSE"; // Convert to uppercase strings

            // Add the request, response, and additional details to the table model
            logTableModel.addRow(new Object[]{sendTime, method, url, status, length, request, response, isValidStr});
            // Apply the custom renderer to the table
            for (int i = 0; i < logTable.getColumnCount(); i++) {
                logTable.getColumnModel().getColumn(i).setCellRenderer(new CustomRenderer());
            }
        });
    }

    // Update request-response viewer when a row in the table is selected
    private void updateRequestResponseViewer() {
        int selectedRow = logTable.getSelectedRow();
        if (selectedRow >= 0) {
            HttpRequest request = (HttpRequest) logTableModel.getValueAt(selectedRow, 5);
            HttpResponse response = (HttpResponse) logTableModel.getValueAt(selectedRow, 6);
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
    // private static final Border PADDING = new EmptyBorder(1, 1, 1, 1);
    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        // Call parent to get default rendering
        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        // Get the actual model row index to ensure consistent coloring after sorting
        int modelRow = table.convertRowIndexToModel(row);

        // Check the isValid flag in the last column to determine if the row should be highlighted
        String isValid = (String) table.getModel().getValueAt(modelRow, 7); // 7th column for isValid
        //Boolean isValid = (Boolean) table.getModel().getValueAt(row, 7); // 7th column for isValid

        if (isSelected) {
            // Use selection colors if the cell is selected
            c.setBackground(table.getSelectionBackground());
            c.setForeground(table.getSelectionForeground());
        } else if ("TRUE".equals(isValid)) {
            // Set the entire row to the highlight color if isValid is true
            c.setBackground(HIGHLIGHT_COLOR);
            c.setForeground(Color.BLACK);
        } else {
            // Apply row banding for non-highlighted rows using the model row index
            if (modelRow % 2 == 0) {
                c.setBackground(EVEN_ROW_COLOR);  // Light gray for even rows
            } else {
                c.setBackground(ODD_ROW_COLOR);   // White for odd rows
            }
            c.setForeground(Color.BLACK);  // Default text color for unselected cells
        }

        // Set cell padding and ensure the renderer is opaque to show background color
        //((JComponent) c).setBorder(PADDING);
        ((JComponent) c).setOpaque(true);

        return c;
    }
}