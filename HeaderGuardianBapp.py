# -*- coding: utf-8 -*-

from burp import IBurpExtender, IContextMenuFactory, ITab, IHttpRequestResponse
from javax.swing import JMenuItem, JPanel, JSplitPane, JTabbedPane, JScrollPane, JTable, JButton, JFileChooser
from javax.swing.border import EmptyBorder
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, Dimension
from java.util import ArrayList
import java.awt.Desktop as Desktop
import java.net.URI as URI
import os

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.printOutput("Header Guardian Extension Loaded")
        self.callbacks.setExtensionName("Header Guardian")

        # Add the context menu
        callbacks.registerContextMenuFactory(self)

        # User Interface
        self.tab = JTabbedPane()
        self.tab.setPreferredSize(Dimension(800, 600))  # Set preferred size for the tabbed pane

        # Add the main tab to the Burp Suite UI
        self.callbacks.customizeUiComponent(self.tab)
        self.callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "Header Guardian"

    def getUiComponent(self):
        return self.tab

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        
        # Create the context menu
        menu_item = JMenuItem("Send to Header Guardian", actionPerformed=lambda x: self.sendToHeaderGuardian(invocation))
        menu_list.add(menu_item)
        
        return menu_list
    
    def sendToHeaderGuardian(self, invocation):
        # Get the selected request
        selected_messages = invocation.getSelectedMessages()
        if selected_messages:
            for message_info in selected_messages:
                self.addRequestTab(message_info)
    
    def addRequestTab(self, message_info):
        # Extract the content of the "Host" header
        request_info = self.helpers.analyzeRequest(message_info)
        headers = request_info.getHeaders()
        host_header = next((header.split(":", 1)[1].strip() for header in headers if header.lower().startswith("host:")), None)
        
        # Name the tab with the content of the "Host" header
        tab_title = host_header if host_header else "Request " + str(self.tab.getTabCount() + 1)
        
        # Create the main panel split vertically
        main_panel = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        # Create the split panel for request and response (horizontal)
        split_panel = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)

        # Burp Suite request and response editor
        request_view = self.callbacks.createMessageEditor(None, False)
        response_view = self.callbacks.createMessageEditor(None, False)

        # Set the content of the editors
        request_view.setMessage(message_info.getRequest(), True)
        response_view.setMessage(message_info.getResponse(), False)

        # Set the editor in the split panel
        split_panel.setLeftComponent(request_view.getComponent())
        split_panel.setRightComponent(response_view.getComponent())
        split_panel.setResizeWeight(0.5)  # Split the window exactly in half
        split_panel.setContinuousLayout(True)
        
        # Add the split panel to the top of the main panel
        main_panel.setTopComponent(split_panel)
        
        # Create the bottom panel for analysis
        analysis_panel = JPanel(BorderLayout())
        
        # Create the table model and table for analysis results
        columns = ["Header", "Current Value", "Expected Value", "Status"]
        table_model = DefaultTableModel(columns, 0)
        analysis_table = JTable(table_model)
        analysis_table.setFillsViewportHeight(True)
        
        # Add the table to a scroll pane
        scroll_pane = JScrollPane(analysis_table)
        
        # Add the scroll pane to the analysis panel
        analysis_panel.add(scroll_pane, BorderLayout.CENTER)
        
        # Perform the analysis and add the result to the table
        self.analyzeRequestResponse(message_info, table_model)
        
        # Add the new sub-tab to the main tab
        main_panel.setBottomComponent(analysis_panel)
        main_panel.setResizeWeight(0.5)  # Split the main window in half between top and bottom
        
        self.tab.addTab(tab_title, main_panel)
        self.tab.setSelectedComponent(main_panel)

        # Create the "Export" button
        export_button = JButton("Export to TXT", actionPerformed=lambda x: self.exportAnalysis(table_model, tab_title))
        analysis_panel.add(export_button, BorderLayout.SOUTH)

    def analyzeRequestResponse(self, message_info, table_model):
        try:
            # Perform the analysis of the headers
            request_headers = self.helpers.analyzeRequest(message_info).getHeaders()
            response_headers = self.helpers.analyzeResponse(message_info.getResponse()).getHeaders() if message_info.getResponse() else []

            # Expected security headers and their correct values
            expected_headers = {
                "X-Frame-Options": "DENY",
                "X-XSS-Protection": "0",
                "X-Content-Type-Options": "nosniff",
                "Content-Type": "charset=UTF-8",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
                "Content-Security-Policy": "default-src 'self'",
                "Access-Control-Allow-Origin": "https://yoursite.com",  
                "Cross-Origin-Opener-Policy": "same-origin",
                "Cross-Origin-Embedder-Policy": "require-corp",
                "Cross-Origin-Resource-Policy": "same-site",
                "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
                "X-DNS-Prefetch-Control": "off"
            }

            # Headers to remove
            headers_to_remove_list = [
                "Server",  # Avoid exposing server information
                "X-Powered-By",  # Avoid exposing technology information
                "X-AspNet-Version",  # Avoid exposing AspNet version information
                "X-AspNetMvc-Version",  # Avoid exposing AspNetMvc version information
                "Expect-CT" 
            ]

            # Check expected headers
            for expected_header, expected_value in expected_headers.items():
                current_value = next((header.split(":", 1)[1].strip() for header in response_headers if header.startswith(expected_header)), None)
                if current_value:
                    if expected_value == current_value:
                        table_model.addRow([expected_header, current_value, expected_value, "Correct"])
                    else:
                        table_model.addRow([expected_header, current_value, expected_value, "Misconfigured"])
                else:
                    table_model.addRow([expected_header, "N/A", expected_value, "Missing"])
            
            # Check unnecessary headers
            for header in response_headers:
                header_name = header.split(":")[0]
                if header_name in headers_to_remove_list:
                    table_model.addRow([header_name, header.split(":", 1)[1].strip(), "N/A", "To Remove"])
        
        except Exception as e:
            self.callbacks.printOutput("Error analyzing request/response: {}".format(str(e)))
        
        # Add final text with hyperlink
        final_text = (
            "<br><br><p>This Extension follows recommendations for HTTP security headers from OWASP. "
            "For more details on best practices for HTTP headers, please refer to the "
            "<a href='https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html'>"
            "OWASP HTTP Headers Cheat Sheet</a>.</p>"
        )

        # Add final text to the bottom of the panel (as HTML)
        if table_model.getRowCount() == 0:
            table_model.addRow(["All security headers are correctly configured.", "", "", ""])

    def exportAnalysis(self, table_model, tab_title):
        try:
            # Open file chooser dialog
            file_chooser = JFileChooser()
            file_chooser.setDialogTitle("Save Analysis as TXT")
            result = file_chooser.showSaveDialog(None)
            
            if result == JFileChooser.APPROVE_OPTION:
                file = file_chooser.getSelectedFile()
                file_path = file.getAbsolutePath()
                
                if not file_path.endswith(".txt"):
                    file_path += ".txt"
                
                # Write the analysis to the selected file
                with open(file_path, "w") as f:
                    f.write("Header Analysis for: {}\n\n".format(tab_title))
                    for row in range(table_model.getRowCount()):
                        header = table_model.getValueAt(row, 0)
                        current_value = table_model.getValueAt(row, 1)
                        expected_value = table_model.getValueAt(row, 2)
                        status = table_model.getValueAt(row, 3)
                        f.write("Header: {}\nCurrent Value: {}\nExpected Value: {}\nStatus: {}\n\n".format(header, current_value, expected_value, status))
                
                self.callbacks.printOutput("Analysis exported successfully to: " + file_path)
        
        except Exception as e:
            self.callbacks.printOutput("Error exporting analysis: {}".format(str(e)))

    def hyperlinkUpdate(self, event):
        if event.getEventType().toString() == "ACTIVATED":
            url = event.getURL().toString()
            if Desktop.isDesktopSupported():
                Desktop.getDesktop().browse(URI(url))
