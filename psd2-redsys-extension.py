# -*- coding: utf-8 -*-
# Burp extension (Jython 2.7) - PSD2
from burp import IBurpExtender, ITab, ISessionHandlingAction
from javax.swing import JPanel, JLabel, JSeparator, JButton, JCheckBox, JFileChooser, JTextField, BoxLayout, JScrollPane, JTextArea
from java.awt import BorderLayout, Dimension, FlowLayout, Font
from java.util import UUID
from java.security import MessageDigest, Signature, KeyFactory
from java.security.spec import PKCS8EncodedKeySpec
from java.security.cert import CertificateFactory
from java.util import Base64
from java.io import FileInputStream, ByteArrayInputStream
import re

PSD2_EXTENSION_NAME = "PSD2-Redsys"
PSD2_EXTENSION_VERSION = "V.2.0"

PSD2_CERTIFICATE_EXTENSIONS = ["x-request-id","digest","signature","tpp-signature-certificate"]
							#"psu-ip-address","tpp-redirect-uri","tpp-redirect-preferred","authorization",

# Extract content of file between two markers
# Used to extract content between "---BEGIN CERTIFICATE---" and "---END CERTIFICATE---"
def _read_pem_base64(filepath, begin_marker, end_marker):
	with open(filepath, "rb") as f:
		raw = f.read()
	try:
		pem = raw.decode("utf-8")
	except:
		raise ValueError("File is not PEM: %s" % filepath)

	pat = re.compile(re.escape(begin_marker) + r"([\s\S]+?)" + re.escape(end_marker))
	m = pat.search(pem)
	if not m:
		raise ValueError("%s ... %s not found in file: %s" % (begin_marker, end_marker, filepath))
	b64 = "".join(m.group(1).split())
	decoder = Base64.getDecoder()
	return decoder.decode(b64)

# Load private PEM key
def load_private_key_pkcs8_pem(key_path):
	key_bytes = _read_pem_base64(key_path, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----")
	kf = KeyFactory.getInstance("RSA")
	spec = PKCS8EncodedKeySpec(key_bytes)
	priv = kf.generatePrivate(spec)
	return priv

# Load CRT certificate
def load_certificate(cert_path):
	cf = CertificateFactory.getInstance("X.509")
	with open(cert_path, "rb") as f:
		raw = f.read()
	try:
		text = raw.decode("utf-8")
	except:
		text = None

	fis = FileInputStream(cert_path)
	try:
		cert = cf.generateCertificate(fis)
		return cert
	finally:
		fis.close()

	if text and "-----BEGIN CERTIFICATE-----" in text:
		# Extract ONLY first CERTIFICATE block
		cert_bytes = _read_pem_base64(cert_path, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----")
		bais = ByteArrayInputStream(cert_bytes)
		cert = cf.generateCertificate(bais)
		bais.close()
		return cert

# Return SHA-256 digest
def calculate_digest(payload_str):
	md = MessageDigest.getInstance("SHA-256")
	b = payload_str.encode("utf-8")
	dig = md.digest(b)
	return "SHA-256=" + Base64.getEncoder().encodeToString(dig)

# Sign with SHA256withRSA return base64
def sign_string(private_key, signing_string):
	sig = Signature.getInstance("SHA256withRSA")
	sig.initSign(private_key)
	sig.update(signing_string.encode("utf-8"))
	signature_bytes = sig.sign()
	return Base64.getEncoder().encodeToString(signature_bytes)

# Get certificate and return it base64. Used to convert CRT file to PEM
def get_cert_b64_from_certobj(cert):
	enc = cert.getEncoded()
	return Base64.getEncoder().encodeToString(enc)

# Build PSD2 signature headers
def get_signature_headers(payload_str, cert_path, key_path):
	cert = load_certificate(cert_path)
	private_key = load_private_key_pkcs8_pem(key_path)

	x_request_id = UUID.randomUUID().toString()

	digest_header = calculate_digest(payload_str)
	headers_to_sign = "digest x-request-id"
	signing_string = "digest: %s\nx-request-id: %s" % (digest_header, x_request_id)
	signature_b64 = sign_string(private_key, signing_string)

	serial = str(cert.getSerialNumber())  # evitar error .toString()
	issuer = cert.getIssuerX500Principal().getName()
	key_id = "SN=%s,CA=%s" % (serial, issuer)

	signature_header = 'keyId="%s",algorithm="sha-256",headers="%s",signature="%s"' % (
		key_id, headers_to_sign, signature_b64
	)
	cert_b64 = get_cert_b64_from_certobj(cert)

	return {
		"X-Request-ID": x_request_id,
		"Digest": digest_header,
		"Signature": signature_header,
		"TPP-Signature-Certificate": cert_b64
	}


# -----------------------------
# Burp extension + UI
# -----------------------------
class BurpExtender(IBurpExtender, ITab, ISessionHandlingAction):
	
	def _makeFieldPanelWithCheckbox(self, label, field, checkbox):
		panel = JPanel(FlowLayout(FlowLayout.LEFT))
		panel.add(checkbox)
		panel.add(JLabel(label))
		field.setPreferredSize(Dimension(300, 25))
		panel.add(field)
		return panel

	# Custom UI methods
	def _makeFieldPanel(self, label, field):
		panel = JPanel(FlowLayout(FlowLayout.LEFT))
		panel.add(JLabel(label))
		field.setPreferredSize(Dimension(300, 25))
		panel.add(field)
		return panel

	def _makeFieldPanelButton(self, button, field):
		panel = JPanel(FlowLayout(FlowLayout.LEFT))
		panel.add(button)
		field.setPreferredSize(Dimension(300, 25))
		panel.add(field)
		return panel

	def _makeFieldPanelCheckbox(self, checkbox):
		panel = JPanel(FlowLayout(FlowLayout.LEFT))
		panel.add(checkbox)
		return panel

	def _makeSectionTitle(self, title):
		label = JLabel(title)
		label.setFont(Font("Dialog", Font.BOLD, 20))
		label.setAlignmentX(0.5)
		self.panel.add(label)

	def _makeSeparator(self):
		sep = JSeparator()
		sep.setMaximumSize(Dimension(100000, 10))
		self.panel.add(sep)


	# Burp UI Mandatory - Tab Panel
	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()

		callbacks.setExtensionName(PSD2_EXTENSION_NAME)
		self._log("Extension %s loaded. %s" % (PSD2_EXTENSION_NAME, PSD2_EXTENSION_VERSION))


		# UI
		self.panel = JPanel()
		self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))
		
		# ----------------- Certificates -----------------
		self._makeSectionTitle("Certificates")
		
		self.certField = JTextField()
		certButton = JButton("Certificate (CRT)", actionPerformed=self.loadCertEvent)
		self.panel.add(self._makeFieldPanelButton(certButton, self.certField))

		self.keyField = JTextField()
		keyButton = JButton("Private Key (PKCS#8 PEM)", actionPerformed=self.loadKeyEvent)
		self.panel.add(self._makeFieldPanelButton(keyButton, self.keyField))

		self._makeSeparator()
		# ----------------- Headers -----------------
		self._makeSectionTitle("Authorization header")
		self.authField = JTextField()
		self.authCheckbox = JCheckBox("", True)
		self.panel.add(self._makeFieldPanelWithCheckbox("Authorization:", self.authField, self.authCheckbox))

		self._makeSeparator()
		# ----------------- Headers -----------------
		self._makeSectionTitle("PSD2 mandatory headers")

		self.psuIpField = JTextField("127.0.0.1")
		self.psuIpCheckbox = JCheckBox("", True)
		self.panel.add(self._makeFieldPanelWithCheckbox("PSU-IP-Address:", self.psuIpField, self.psuIpCheckbox))
		
		self.tppRedirectUriField = JTextField("http://localhost:8080/callback")
		self.tppRedirectUriCheckbox = JCheckBox("", True)
		self.panel.add(self._makeFieldPanelWithCheckbox("TPP-Redirect-URI:", self.tppRedirectUriField, self.tppRedirectUriCheckbox))
		
		self.tppRedirectPreferredField = JTextField("true")
		self.tppRedirectPreferredCheckbox = JCheckBox("", True)
		self.panel.add(self._makeFieldPanelWithCheckbox("TPP-Redirect-Preferred:", self.tppRedirectPreferredField, self.tppRedirectPreferredCheckbox))

		self.overwriteCheckbox = JCheckBox("Overwrite headers", False)  # por defecto false
		self.panel.add(self._makeFieldPanelCheckbox(self.overwriteCheckbox))

		self._makeSeparator()
		# ----------------- Log -----------------
		self._makeSectionTitle("Log")
		self.logArea = JTextArea()
		self.logArea.setEditable(False)
		self.logArea.setLineWrap(True)
		self.logArea.setWrapStyleWord(True)
		scroll = JScrollPane(self.logArea)
		scroll.setPreferredSize(Dimension(600, 450))
		self.panel.add(scroll)

		callbacks.addSuiteTab(self)
		callbacks.registerSessionHandlingAction(self)

	# Burp UI Mandatory - Tab Name
	def getTabCaption(self):
		return "PSD2"

	# Burp UI Mandatory
	def getUiComponent(self):
		return self.panel

	# UI Buttons Events
	def loadCertEvent(self, event):
		chooser = JFileChooser()
		if chooser.showOpenDialog(self.panel) == JFileChooser.APPROVE_OPTION:
			f = chooser.getSelectedFile()
			path = f.getAbsolutePath()
			self.certField.setText(path)

	def loadKeyEvent(self, event):
		chooser = JFileChooser()
		if chooser.showOpenDialog(self.panel) == JFileChooser.APPROVE_OPTION:
			f = chooser.getSelectedFile()
			path = f.getAbsolutePath()
			self.keyField.setText(path)

	# Custom log 
	def _log(self, txt):
		try:
			txt = "[PSD2] " + txt
			print(txt)
			self.logArea.append(txt + "\n")
		except:
			pass


	# -----------------------------
	# New Session Handling Action
	# -----------------------------

	def getActionName(self):
		return "PSD2 - Sign Request"


	def performAction(self, currentRequest, macroItems):
		try:
			request_bytes = currentRequest.getRequest()
			analyzed = self._helpers.analyzeRequest(request_bytes)
			headers = list(analyzed.getHeaders())
			body_bytes = request_bytes[analyzed.getBodyOffset():]
			body_str = self._helpers.bytesToString(body_bytes)

			cert_path = self.certField.getText().strip()
			key_path = self.keyField.getText().strip()

			if not cert_path:
				self._log("Skipping - Certificate unassigned")
				return

			if not key_path:
				self._log("Skipping - Private key unassigned")
				return

			new_headers = []

			# PSD2 mandatory headers - From UI
			extra_headers = {}

			if self.psuIpCheckbox.isSelected():
				extra_headers["PSU-IP-Address"] = self.psuIpField.getText().strip()

			if self.tppRedirectUriCheckbox.isSelected():
				extra_headers["TPP-Redirect-URI"] = self.tppRedirectUriField.getText().strip()

			if self.tppRedirectPreferredCheckbox.isSelected():
				extra_headers["TPP-Redirect-Preferred"] = self.tppRedirectPreferredField.getText().strip()

			if self.authCheckbox.isSelected():
				extra_headers["Authorization"] = self.authField.getText().strip()

			# Overwrite headers logic
			extensions_to_overwrite = []

			for header in PSD2_CERTIFICATE_EXTENSIONS:
				extensions_to_overwrite.append(header)

			for header in extra_headers.keys():
				extensions_to_overwrite.append(header.lower())

			if self.overwriteCheckbox.isSelected():
				for header in headers:
					if header.split(":")[0].lower() not in extensions_to_overwrite:
						new_headers.append(header)
			else:
				new_headers = headers

			# Add extra headers
			for k, v in extra_headers.items():
				if v and len(v) > 0:
					new_headers.append(k + ": " + v)
					self._log("Added header -> %s" % k)
				else:
					self._log("Skipping - Header %s missing value" % k)
					return

			# Add signature headers
			try:
				sig_headers = get_signature_headers(body_str, cert_path, key_path)
				for k, v in sig_headers.items():
					new_headers.append(k + ": " + v)
					self._log("Added signature header -> %s" % k)

			except Exception as e:
				self._log("ERROR while signing > %s" % str(e))
				return

			# Update intercepted request
			new_request = self._helpers.buildHttpMessage(new_headers, body_bytes)
			currentRequest.setRequest(new_request)

			self._log("Request signed successfully")
			self._log("-"*100)

		except Exception as e:
			self._log("ERROR > %s" % str(e))
