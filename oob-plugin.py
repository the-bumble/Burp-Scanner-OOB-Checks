"""
@author theBumble

A Burp extension for adding additional payloads to active scanner that require
out-of-band validation.
"""
from burp import IBurpExtender, IScannerCheck, ITab
from javax.swing import JPanel, GroupLayout, JTextField, JFileChooser, \
    JButton, DefaultListModel, JList, JScrollPane, JComboBox, JLabel, \
    SwingConstants, ListCellRenderer
from java.awt import Color, Font
from java.awt.Toolkit import getDefaultToolkit
from java.awt.datatransfer import DataFlavor
import StringIO
import array

callbacks = None
helpers = None


class URLEncoding:
    NoEncoding = 0
    Encoding = 1
    Both = 2


def request(basePair, insertionPoint, attack, URLEncode):
    if URLEncode:
        req = insertionPoint.buildRequest(attack)
    else:
        req = insertionPoint.buildRequest(attack).tostring()
        (start, end) = insertionPoint.getPayloadOffsets(attack)
        req = req[:start] + attack + req[end:]
        req = array.array('b', req.encode())
    return callbacks.makeHttpRequest(basePair.getHttpService(), req)


class OOBCheck(IScannerCheck):
    def __init__(self, tab_ref):
        self.gui = tab_ref

    def doActiveScan(self, basePair, insertionPoint):
        for payload in self.gui.getOOBList():
            encoding = self.gui.getURLEncoding()
            if encoding == URLEncoding.Encoding or encoding == URLEncoding.Both:
                request(basePair, insertionPoint, payload, True)

            if encoding == URLEncoding.NoEncoding or \
               encoding == URLEncoding.Both:
                request(basePair, insertionPoint, payload, False)
        return []

    def doPassiveScan(self, basePair):
        return []


"""
    Jython Swing Code
"""


class ListRenderer(JLabel, ListCellRenderer):
    ALT_CELL_COLOR = Color(0xF2F2F2)
    BG_COLOR = Color(0xFBFBFB)
    SELECT_COLOR = Color(0xFFCD81)

    def __init__(self):
        self.setOpaque(True)
        self.putClientProperty("html.disable", True)

    def getListCellRendererComponent(self, mList, value, idx,
                                     isSelected, hasFocus):
        self.setText(value)
        if idx % 2 == 0:
            self.setBackground(Color.WHITE)
        else:
            self.setBackground(self.ALT_CELL_COLOR)

        if isSelected:
            self.setBackground(self.SELECT_COLOR)
        return self


class CustomTab(ITab):
    URL_NON_ENCODE_IDX = 0
    URL_ENCODE_IDX = 1

    def remove_element(self, evt):
        for item in self.cbList.getSelectedIndices()[::-1]:
            self.listModel.remove(item)

    def add_element(self, evt):
        self.listModel.addElement(self.cbText.getText())
        self.cbText.setText("")

    def add_file(self, evt):
        fc = JFileChooser()
        ret = fc.showOpenDialog(self.tab)
        if ret == JFileChooser.APPROVE_OPTION:
            with open(fc.getSelectedFile().getCanonicalPath()) as fd:
                for line in fd:
                    self.listModel.addElement(line)

    def clear_elements(self, evt):
        self.listModel.removeAllElements()

    def paste_elements(self, evt):
        data = getDefaultToolkit().getSystemClipboard().getData(
            DataFlavor.stringFlavor
        )
        for payload in StringIO.StringIO(data):
            if payload and not payload.isspace():
                self.listModel.addElement(payload)

    def getOOBList(self):
        return self.listModel.toArray()

    def getURLEncoding(self):
        idx = self.cbDropDown.getSelectedIndex()
        if idx == self.URL_NON_ENCODE_IDX:
            return URLEncoding.NoEncoding
        elif idx == self.URL_ENCODE_IDX:
            return URLEncoding.Encoding
        else:
            return URLEncoding.Both

    def getTabCaption(self):
        return("OOB")

    def getUiComponent(self):
        return self.tab

    def __init__(self):
        self.listModel = DefaultListModel()

        self.cbTitle = JLabel("Out-of-band Payloads")
        self.cbTitle.setFont(self.cbTitle.getFont().deriveFont(14.0))
        self.cbTitle.setFont(self.cbTitle.getFont().deriveFont(Font.BOLD))

        self.cbSubTitle = JLabel("Add payloads to active scanner that interact "
                                 "with out-of-band services (e.g., XSSHunter)")
        self.cbSubTitle.setFont(self.cbSubTitle.getFont().deriveFont(12.0))

        self.cbList = JList(self.listModel)
        self.cbList.setCellRenderer(ListRenderer())
        self.cbList.setVisibleRowCount(10)

        self.listScrollPane = JScrollPane(self.cbList)
        self.cbText = JTextField(actionPerformed=self.add_element)
        self.cbRemoveButton = JButton("Remove",
                                      actionPerformed=self.remove_element)
        self.cbLoadButton = JButton("Load...",
                                    actionPerformed=self.add_file)
        self.cbPasteButton = JButton("Paste",
                                     actionPerformed=self.paste_elements)
        self.cbClearButton = JButton("Clear",
                                     actionPerformed=self.clear_elements)

        self.cbAddButton = JButton("Add", actionPerformed=self.add_element)

        self.cbDropDownLabel = JLabel("Payload Encoding: ")
        self.cbDropDown = JComboBox()
        self.cbDropDown.addItem("Non URL Encoded")
        self.cbDropDown.addItem("URL Encoded")
        self.cbDropDown.addItem("Both (two requests per payload)")

        self.grpOOB = JPanel()

        grpLayout = GroupLayout(self.grpOOB)
        self.grpOOB.setLayout(grpLayout)
        grpLayout.linkSize(SwingConstants.HORIZONTAL,
                           self.cbRemoveButton,
                           self.cbLoadButton,
                           self.cbPasteButton,
                           self.cbClearButton,
                           self.cbAddButton)
        grpLayout.setAutoCreateGaps(True)
        grpLayout.setAutoCreateContainerGaps(True)
        grpLayout.setHorizontalGroup(
            grpLayout.createSequentialGroup()
            .addGroup(grpLayout.createParallelGroup()
                .addComponent(self.cbTitle)
                .addGroup(grpLayout.createParallelGroup()
                    .addComponent(self.cbRemoveButton)
                    .addComponent(self.cbLoadButton)
                    .addComponent(self.cbPasteButton)
                    .addComponent(self.cbClearButton)
                 )
                .addComponent(self.cbAddButton)
                .addComponent(self.cbDropDownLabel)
            )
            .addGroup(grpLayout.createParallelGroup()
                .addComponent(self.cbSubTitle)
                .addComponent(self.listScrollPane)
                .addComponent(self.cbText)
                .addComponent(self.cbDropDown)
            )
        )
        grpLayout.setVerticalGroup(
            grpLayout.createSequentialGroup()
            .addGroup(grpLayout.createParallelGroup()
                .addComponent(self.cbTitle)
            )
            .addGroup(grpLayout.createParallelGroup()
                .addComponent(self.cbSubTitle)
            )
            .addGroup(grpLayout.createParallelGroup()
                .addGroup(grpLayout.createSequentialGroup()
                    .addComponent(self.cbPasteButton)
                    .addComponent(self.cbLoadButton)
                    .addComponent(self.cbRemoveButton)
                    .addComponent(self.cbClearButton)
                 )
                .addComponent(self.listScrollPane)
            )
            .addGroup(grpLayout.createParallelGroup()
                .addComponent(self.cbAddButton)
                .addComponent(self.cbText)
            )
            .addGroup(grpLayout.createParallelGroup()
                .addComponent(self.cbDropDownLabel)
                .addComponent(self.cbDropDown)
            )
        )

        # Tab Layout
        self.tab = JPanel()
        tabLayout = GroupLayout(self.tab)
        self.tab.setLayout(tabLayout)
        tabLayout.setAutoCreateGaps(True)
        tabLayout.setAutoCreateContainerGaps(True)
        tabLayout.setHorizontalGroup(
            tabLayout.createSequentialGroup()
            .addGroup(tabLayout.createParallelGroup()
                .addComponent(self.grpOOB,
                              GroupLayout.PREFERRED_SIZE,
                              GroupLayout.PREFERRED_SIZE,
                              GroupLayout.PREFERRED_SIZE)
            )
        )
        tabLayout.setVerticalGroup(
            tabLayout.createSequentialGroup()
            .addGroup(tabLayout.createParallelGroup()
                .addComponent(self.grpOOB,
                              GroupLayout.PREFERRED_SIZE,
                              GroupLayout.PREFERRED_SIZE,
                              GroupLayout.PREFERRED_SIZE)
            )
        )


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, burp_callbacks):
        global callbacks, helpers

        callbacks = burp_callbacks
        helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Out-of-band Checks")
        print '[*] Out-of-band Checks initializing...'

        tab = CustomTab()
        callbacks.registerScannerCheck(OOBCheck(tab))
        callbacks.addSuiteTab(tab)

        print '[*] Out-of-band Checks extension loaded successfully.'
